"""Compile host tests and cross-check Java changes using the original Python crypto.

No game files, device identifiers or keys are included in this source directory.
All fixture-derived outputs are encrypted and temporary; no plaintext is exported.
"""
from pathlib import Path
import argparse
import configparser
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

PROJECT = Path(__file__).resolve().parents[1]


def java_tool(name):
    suffix = ".exe" if os.name == "nt" else ""
    if os.environ.get("JAVA_HOME"):
        candidate = Path(os.environ["JAVA_HOME"]) / "bin" / (name + suffix)
        if not candidate.is_file():
            raise RuntimeError(f"JAVA_HOME does not contain {name}; select a JDK 17+ installation.")
        return str(candidate)
    candidate = shutil.which(name)
    if not candidate:
        raise RuntimeError(f"{name} not found; set JAVA_HOME or add JDK 17+ bin to PATH.")
    return candidate


def parse(text):
    # UE4 legitimately repeats unrelated array entries such as Core.System.Paths.
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read_string(text)
    return parser


def independently_remove_overrides(text, allowed):
    """Independent fixture oracle: retain whole original lines except exact scoped assignments."""
    section = ""
    kept = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        header = re.fullmatch(r"[ \t]*\[([^\]\r\n]+)\][ \t]*(?:[;#].*)?", body)
        if header:
            section = header.group(1).lower()
        else:
            field = re.match(r"[ \t]*([^= \t]+)[ \t]*=", body)
            if field and field.group(1).lower() in allowed.get(section, set()):
                continue
        kept.append(line)
    return "".join(kept)


def main():
    parser = argparse.ArgumentParser(description="Run synthetic core checks, or explicitly supplied private fixture checks.")
    parser.add_argument("--synthetic", action="store_true", help="Run synthetic tests only (the default).")
    parser.add_argument("--fixture", type=Path, help="Private ZIP containing 1/Engine.ini, 1/Game.ini and 1/UserGameplay.ini.")
    parser.add_argument("--library", type=Path, help="Matching private ARM64 libUE4.so.")
    parser.add_argument("--reference-dir", type=Path, help="Private directory containing the independent config_crypto.py reference.")
    options = parser.parse_args()
    supplied = [options.fixture is not None, options.library is not None, options.reference_dir is not None]
    if any(supplied) and (not all(supplied) or options.synthetic):
        parser.error("Use all of --fixture, --library and --reference-dir together, without --synthetic.")
    real = all(supplied)
    fixture, library = options.fixture, options.library
    if real:
        for label, path in [("fixture", fixture), ("library", library), ("reference", options.reference_dir / "config_crypto.py")]:
            if not path.is_file():
                parser.error(f"Explicit {label} file does not exist: {path}")
    sources = list((PROJECT / "app/src/main/java/io/github/deltaconfig/core").glob("*.java"))
    sources += [PROJECT / "tests/CoreTests.java", PROJECT / "tests/LibraryMaskResolverTests.java",
                PROJECT / "tests/ConfigCompatibilityTests.java"]
    checks = 0
    with tempfile.TemporaryDirectory(prefix="deltaconfig-core-") as temporary:
        scratch = Path(temporary)
        classes = scratch / "classes"
        classes.mkdir()
        subprocess.run([java_tool("javac"), "-encoding", "UTF-8", "--release", "8",
                        "-d", str(classes), *map(str, sources)], check=True)
        arguments = [str(fixture), str(library), str(scratch / "outputs")] if real else []
        subprocess.run([java_tool("java"), "-cp", str(classes), "CoreTests", *arguments], check=True)
        subprocess.run([java_tool("java"), "-cp", str(classes), "LibraryMaskResolverTests"], check=True)
        subprocess.run([java_tool("java"), "-cp", str(classes), "ConfigCompatibilityTests"], check=True)
        if not real:
            print("Synthetic tests completed; no private game files were read. Supply explicit fixture options for optional checks.")
            return
        sys.path.insert(0, str(options.reference_dir.resolve()))
        import config_crypto as reference
        with zipfile.ZipFile(fixture) as archive:
            engine = archive.read("1/Engine.ini")
            gameplay = archive.read("1/UserGameplay.ini")
            game = archive.read("1/Game.ini")
        mask = reference.load_fixed_mask(library)
        decoded_hash = reference.decode_text(reference.decrypt_token(reference.get_field(gameplay, "Hash"), mask).payload)
        key = reference.repeat_xor(mask, bytes.fromhex(decoded_hash))
        original_text = reference.decode_text(reference.decrypt_token(reference.get_field(engine), key).payload)
        assert reference.replace_text_token(engine, original_text, key) == engine
        checks += 1
        for prefix, quality, fps, target, display in [("native", 5, 9, 8192, 144), ("reduced", 2, 8, 1080, 120), ("fps165", 4, 10, 8192, 165), ("fps185", 4, 11, 8192, 185)]:
            changed_engine = (scratch / f"outputs/{prefix}-Engine.ini").read_bytes()
            text = reference.decode_text(reference.decrypt_token(reference.get_field(changed_engine), key).payload)
            assert reference.replace_text_token(changed_engine, text, key) == changed_engine
            config = parse(text)
            assert config.getint("DFMPerfGearConfig", "DFMQualityLevel") == quality
            assert config.getint("DFMPerfGearConfig", "DFMFPSLevel") == fps
            assert config.getint("QualityFPSSetting", "Unlimit") == 1
            assert config.getint("SystemSettings", "PerfGear.SmallPadSize") == 0
            assert config.getint("SystemSettings", f"DFMDeviceFrame.White{display}fps") == 1
            changed_game = (scratch / f"outputs/{prefix}-Game.ini").read_bytes()
            game_config = parse(changed_game.decode("utf-8-sig"))
            assert game_config.getint("LuaFrontEnd", "LastHotUpdateVersion") == parse(game.decode("utf-8-sig")).getint("LuaFrontEnd", "LastHotUpdateVersion")
            pad = game_config["/Script/PerfGear.PerfGearAndroidPadSizeConfig"]
            assert set(pad) == {"smallpadconfig", "midpadconfig", "bigpadconfig"}
            for value in pad.values():
                assert value.count("BackBuffer=8192") == 5
                for field in ["UltraLowResolution", "LowResolution", "MidResolution", "HighResolution", "UltraHighResolution", "SuperResolution"]:
                    assert len(re.findall(r"(?<=[,(])" + re.escape(field) + "=" + str(target) + r"(?=[,)])", value)) == 5
                    checks += 1
            checks += 9
        reset_engine = (scratch / "outputs/reset-Engine.ini").read_bytes()
        reset_source_engine = (scratch / "outputs/reset-source-Engine.ini").read_bytes()
        reset_source_text = reference.decode_text(reference.decrypt_token(reference.get_field(reset_source_engine), key).payload)
        reset_text = reference.decode_text(reference.decrypt_token(reference.get_field(reset_engine), key).payload)
        assert reference.replace_text_token(reset_engine, reset_text, key) == reset_engine
        engine_targets = {
            "dfmperfgearconfig": {"dfmqualitylevel", "dfmfpslevel"},
            "qualityfpssetting": {"unlimit"},
            "systemsettings": {"perfgear.smallpadsize", *(
                f"dfmdeviceframe.white{fps}fps" for fps in [90, 120, 144, 165, 185])},
        }
        assert reset_text == independently_remove_overrides(reset_source_text, engine_targets)
        reset_config = parse(reset_text)
        for section, names in engine_targets.items():
            matching = next((name for name in reset_config.sections() if name.lower() == section), None)
            for name in names:
                assert matching is None or not reset_config.has_option(matching, name)
                checks += 1
        reset_source_game = (scratch / "outputs/reset-source-Game.ini").read_bytes()
        original_game_text = reset_source_game.decode("utf-8-sig")
        game_targets = {"/script/perfgear.perfgearandroidpadsizeconfig": {"smallpadconfig", "midpadconfig", "bigpadconfig"}}
        reset_game = (scratch / "outputs/reset-Game.ini").read_bytes()
        assert reset_game.decode("utf-8-sig") == independently_remove_overrides(original_game_text, game_targets)
        assert reset_game.startswith(b"\xef\xbb\xbf") == reset_source_game.startswith(b"\xef\xbb\xbf")
        reset_game_config = parse(reset_game.decode("utf-8-sig"))
        assert reset_game_config.get("LuaFrontEnd", "LastHotUpdateVersion") == parse(original_game_text).get("LuaFrontEnd", "LastHotUpdateVersion")
        for name in game_targets["/script/perfgear.perfgearandroidpadsizeconfig"]:
            assert not reset_game_config.has_option("/Script/PerfGear.PerfGearAndroidPadSizeConfig", name)
            checks += 1
        checks += 5
        print(f"Python independent authentication/field checks passed: {checks}; temporary outputs removed on exit.")


if __name__ == "__main__":
    main()
