import io.github.deltaconfig.RootShell;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;

/** Actual route builder and identity parser, exercised without su or game writes. */
public final class RootNamespaceTests {
    private static int checks;
    public static void main(String[] args) throws Exception {
        Method advertised = method("advertisedMountOption", String.class);
        equal("--mount-master", advertised.invoke(null, "MagiskSU\n -mm, --mount-master  Force global mount namespace"));
        equal("-M", advertised.invoke(null, "Usage: su [-M, --other]\n"));
        check(advertised.invoke(null, "MagiskSU without declared mount option") == null);
        check(advertised.invoke(null, "--mount-master-fake -More") == null);
        equal("-M", advertised.invoke(null, "-M"));

        Class<?> routeType = Class.forName("io.github.deltaconfig.RootShell$Route");
        Constructor<?> create = routeType.getDeclaredConstructor(String.class, String.class); create.setAccessible(true);
        Method arguments = routeType.getDeclaredMethod("arguments", String.class); arguments.setAccessible(true);
        String command = "cat '/a with spaces/Engine.ini'; printf '%s' '\\0'";
        String[] ordinary = (String[]) arguments.invoke(create.newInstance(null, null), command);
        check(Arrays.equals(new String[]{"su", "-c", command}, ordinary));
        String[] master = (String[]) arguments.invoke(create.newInstance("--mount-master", null), command);
        check(Arrays.equals(new String[]{"su", "--mount-master", "-c", command}, master));
        String[] enter = (String[]) arguments.invoke(create.newInstance(null, "nsenter"), command);
        check(enter.length == 3);
        equal("nsenter --mount=/proc/1/ns/mnt -- /system/bin/sh -c " + RootShell.quote(command), enter[2]);
        String[] toybox = (String[]) arguments.invoke(create.newInstance("-M", "/system/bin/toybox nsenter"), command);
        check(toybox.length == 4);
        equal("-M", toybox[1]);
        equal("/system/bin/toybox nsenter --mount=/proc/1/ns/mnt -- /system/bin/sh -c " + RootShell.quote(command), toybox[3]);

        Method parser = method("parseProbe", String.class, boolean.class);
        Object valid = parser.invoke(null, "0\nmnt:[123]\nmnt:[123]\nOK\n", true);
        Field state = valid.getClass().getDeclaredField("fileState"); state.setAccessible(true);
        equal("OK", state.get(valid));
        Object masterProbe = parser.invoke(null, "0\nmnt:[123]\nmnt:[456]\nMISSING\n", false);
        equal("MISSING", state.get(masterProbe));
        check(parser.invoke(null, "0\nmnt:[123]\nunavailable\nOK\n", false) != null);
        rejects(parser, "0\nmnt:[123]\nmnt:[456]\nOK\n", true);
        rejects(parser, "0\nmnt:[123]\nunavailable\nOK\n", true);
        rejects(parser, "2000\nmnt:[123]\nmnt:[123]\nOK\n", false);
        rejects(parser, "0\nmnt:[bad]\nmnt:[123]\nOK\n", false);
        rejects(parser, "0\nmnt:[123]\nmnt:[123]\nPASS\n", false);
        rejects(parser, "0\nmnt:[123]\nmnt:[123]\nOK\nextra\n", false);
        check(parser.invoke(null, "0\r\nmnt:[123]\r\nmnt:[123]\r\nOK\r\n", true) != null);
        for (String fileState : new String[]{"OK", "MISSING", "NOT_REGULAR", "UNREADABLE", "SYMLINK"})
            check(parser.invoke(null, "0\nmnt:[123]\nmnt:[123]\n" + fileState + "\n", true) != null);

        Method probe = method("probeCommand", String.class);
        String specialPath = "/data/user/0/example/files/a'$(id);`x`/Engine.ini";
        String script = (String) probe.invoke(null, specialPath);
        check(script.contains(RootShell.quote(specialPath)));
        check(script.contains(": < " + RootShell.quote(specialPath)));
        check(!script.contains("cat "));
        check(!script.contains(" > "));
        Method guard = method("guard", String.class);
        String protectedCommand = (String) guard.invoke(null, "mnt:[123]");
        check(protectedCommand.contains("$(id -u)"));
        check(protectedCommand.contains("readlink /proc/$$/ns/mnt"));
        check(protectedCommand.contains("exit 49"));
        check(protectedCommand.contains("exit 50"));
        check(!protectedCommand.contains("stdin"));
        System.out.println("Root namespace host checks: " + checks + " passed (no su/device writes)");
    }
    private static Method method(String name, Class<?>... types) throws Exception {
        Method value = RootShell.class.getDeclaredMethod(name, types); value.setAccessible(true); return value;
    }
    private static void rejects(Method method, Object... values) throws Exception {
        try { method.invoke(null, values); throw new AssertionError("Invalid probe accepted"); }
        catch (InvocationTargetException expected) { check(expected.getCause() instanceof IOException); }
    }
    private static void equal(Object expected, Object actual) { check(expected.equals(actual)); }
    private static void check(boolean value) { if (!value) throw new AssertionError("check " + (checks + 1)); checks++; }
}
