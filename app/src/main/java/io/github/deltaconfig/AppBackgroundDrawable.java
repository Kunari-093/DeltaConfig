package io.github.deltaconfig;

import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.PixelFormat;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;

/** Renders the supplied picture unchanged, with opacity confined to this decorative layer. */
final class AppBackgroundDrawable extends Drawable {
    private static final int IMAGE_ALPHA = 102; // 40% visible over the warm pink surface.
    private final Bitmap image;
    private final Paint imagePaint = new Paint(Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG);
    private final Paint basePaint = new Paint();
    private final RectF destination = new RectF();
    private int drawableAlpha = 255;

    AppBackgroundDrawable(Resources resources) {
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inScaled = false;
        image = BitmapFactory.decodeResource(resources, R.drawable.app_background, options);
        basePaint.setColor(resources.getColor(R.color.background, null));
        imagePaint.setAlpha(IMAGE_ALPHA);
    }

    @Override protected void onBoundsChange(Rect bounds) {
        if (image == null) return;
        float scale = Math.max(bounds.width() / (float) image.getWidth(), bounds.height() / (float) image.getHeight());
        float width = image.getWidth() * scale, height = image.getHeight() * scale;
        // A slightly higher vertical anchor retains the face in wide windows.
        float left = bounds.left + (bounds.width() - width) * .5f;
        float top = bounds.top + (bounds.height() - height) * .35f;
        destination.set(left, top, left + width, top + height);
    }

    @Override public void draw(Canvas canvas) {
        int checkpoint = canvas.save();
        canvas.clipRect(getBounds());
        canvas.drawRect(getBounds(), basePaint);
        if (image != null) canvas.drawBitmap(image, null, destination, imagePaint);
        canvas.restoreToCount(checkpoint);
    }

    @Override public void setAlpha(int alpha) {
        drawableAlpha = Math.max(0, Math.min(255, alpha));
        basePaint.setAlpha(drawableAlpha);
        imagePaint.setAlpha(IMAGE_ALPHA * drawableAlpha / 255);
        invalidateSelf();
    }

    @Override public int getAlpha() { return drawableAlpha; }
    @Override public void setColorFilter(ColorFilter filter) { imagePaint.setColorFilter(filter); invalidateSelf(); }
    @Override public int getOpacity() { return drawableAlpha == 255 ? PixelFormat.OPAQUE : PixelFormat.TRANSLUCENT; }
}
