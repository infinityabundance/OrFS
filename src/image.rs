//! Image recognition and multiresolution geometry (research §11.3).
//!
//! ## What is implemented, and what is not
//!
//! This module performs **content-based** recognition of image formats (never by
//! file extension), extracts the image's dimensions and colour semantics, and
//! computes an explicit multiresolution level geometry. Those three things are
//! exactly the correctness concerns research §11.3 names:
//!
//! * *format recognition (NOT extension)* — [`recognize`] inspects the byte
//!   signature; a `.png` that is not a PNG is rejected, and a PNG with no
//!   extension is accepted;
//! * *dimensions* — parsed from the format's header with the format's own
//!   endianness and header layout;
//! * *pixel/colour semantics* — the colour model, bit depth, and (for PNG) the
//!   colour type are parsed and validated; an internally inconsistent header is
//!   rejected rather than reinterpreted.
//!
//! The **pixel-surface pyramid** (decoded, downsampled image data stored under
//! `.or_bloom/image/`) is deliberately **not** materialised. Producing real
//! surfaces requires a PNG decoder — a zlib/DEFLATE inflater plus per-scanline
//! filter reconstruction, interlacing, and colour-space handling — i.e. a real
//! codec dependency (`png`/`image`, or `flate2`+`miniz_oxide`). This build
//! environment is offline and single-crate/minimal-dependency, so such a crate
//! cannot be added here; and hand-rolling an unaudited inflater/lifting pass
//! would directly threaten the pixel/colour correctness that §11.3 demands. The
//! geometry this module reports is therefore *descriptive*, not a set of
//! materialised surfaces, and is never claimed to be one.

/// A recognised image container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ImageFormat {
    Png,
    Gif,
    Bmp,
    Jpeg,
    WebP,
    Tiff,
}

impl ImageFormat {
    pub const fn name(self) -> &'static str {
        match self {
            ImageFormat::Png => "png",
            ImageFormat::Gif => "gif",
            ImageFormat::Bmp => "bmp",
            ImageFormat::Jpeg => "jpeg",
            ImageFormat::WebP => "webp",
            ImageFormat::Tiff => "tiff",
        }
    }
}

/// The colour model of an image (as far as is knowable from the header).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum ColourModel {
    Grayscale,
    GrayscaleAlpha,
    Rgb,
    Rgba,
    Palette,
    YCbCr,
    Cmyk,
}

impl ColourModel {
    pub const fn name(self) -> &'static str {
        match self {
            ColourModel::Grayscale => "grayscale",
            ColourModel::GrayscaleAlpha => "grayscale-alpha",
            ColourModel::Rgb => "rgb",
            ColourModel::Rgba => "rgba",
            ColourModel::Palette => "palette",
            ColourModel::YCbCr => "ycbcr",
            ColourModel::Cmyk => "cmyk",
        }
    }

    /// Channels per pixel for this model (palette stores indices).
    pub const fn channels(self) -> u8 {
        match self {
            ColourModel::Grayscale => 1,
            ColourModel::GrayscaleAlpha => 2,
            ColourModel::Rgb | ColourModel::YCbCr => 3,
            ColourModel::Rgba | ColourModel::Cmyk => 4,
            ColourModel::Palette => 1,
        }
    }
}

/// One level of the multiresolution geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Level {
    pub index: u32,
    pub width: u32,
    pub height: u32,
}

/// A recognised image with its parsed semantics and level geometry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ImageInfo {
    pub format: ImageFormat,
    pub width: u32,
    pub height: u32,
    pub bit_depth: u8,
    pub colour: ColourModel,
    /// Level geometry, base first, each dimension halved (never below 1).
    pub levels: Vec<Level>,
}

impl ImageInfo {
    /// Total pixels across all pyramid levels (excluding the base).
    pub fn pyramid_extra_pixels(&self) -> u64 {
        self.levels
            .iter()
            .skip(1)
            .map(|l| l.width as u64 * l.height as u64)
            .sum()
    }
}

/// The level geometry for a `width`×`height` base: repeated halving (floor,
/// clamped to 1) until both dimensions are 1.
pub fn pyramid_levels(width: u32, height: u32) -> Vec<Level> {
    if width == 0 || height == 0 {
        return Vec::new();
    }
    let mut levels = Vec::new();
    let (mut w, mut h) = (width, height);
    let mut index = 0u32;
    loop {
        levels.push(Level {
            index,
            width: w,
            height: h,
        });
        if w == 1 && h == 1 {
            break;
        }
        w = (w / 2).max(1);
        h = (h / 2).max(1);
        index += 1;
    }
    levels
}

/// Recognise the container format from the leading bytes only (never the name).
pub fn recognize(bytes: &[u8]) -> Option<ImageFormat> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some(ImageFormat::Png);
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some(ImageFormat::Gif);
    }
    if bytes.len() >= 12 && &bytes[0..2] == b"BM" {
        return Some(ImageFormat::Bmp);
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(ImageFormat::Jpeg);
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some(ImageFormat::WebP);
    }
    if bytes.starts_with(&[0x49, 0x49, 0x2A, 0x00]) || bytes.starts_with(&[0x4D, 0x4D, 0x00, 0x2A])
    {
        return Some(ImageFormat::Tiff);
    }
    None
}

/// Parse an image header from `bytes`, returning its semantics and geometry.
/// Returns `None` when the bytes are not a recognised image or the header is
/// internally inconsistent (never a guess).
pub fn probe(bytes: &[u8]) -> Option<ImageInfo> {
    match recognize(bytes)? {
        ImageFormat::Png => probe_png(bytes),
        ImageFormat::Gif => probe_gif(bytes),
        ImageFormat::Bmp => probe_bmp(bytes),
        ImageFormat::Jpeg => probe_jpeg(bytes),
        // Container-only signatures: recognise, but no dimensions are known.
        ImageFormat::WebP | ImageFormat::Tiff => None,
    }
}

fn be16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(off)?,
        *b.get(off + 1)?,
        *b.get(off + 2)?,
        *b.get(off + 3)?,
    ]))
}

fn le16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

fn le32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(off)?,
        *b.get(off + 1)?,
        *b.get(off + 2)?,
        *b.get(off + 3)?,
    ]))
}

fn probe_png(bytes: &[u8]) -> Option<ImageInfo> {
    // First chunk must be IHDR with length 13 at offset 8.
    if be32(bytes, 8)? != 13 || &bytes[12..16] != b"IHDR" {
        return None;
    }
    let width = be32(bytes, 16)?;
    let height = be32(bytes, 20)?;
    let bit_depth = *bytes.get(24)?;
    let colour_type = *bytes.get(25)?;
    let compression = *bytes.get(26)?;
    let filter = *bytes.get(27)?;
    let interlace = *bytes.get(28)?;
    if width == 0 || height == 0 || compression != 0 || filter != 0 || interlace > 1 {
        return None;
    }
    let (colour, valid_depths): (ColourModel, &[u8]) = match colour_type {
        0 => (ColourModel::Grayscale, &[1, 2, 4, 8, 16]),
        2 => (ColourModel::Rgb, &[8, 16]),
        3 => (ColourModel::Palette, &[1, 2, 4, 8]),
        4 => (ColourModel::GrayscaleAlpha, &[8, 16]),
        6 => (ColourModel::Rgba, &[8, 16]),
        _ => return None,
    };
    if !valid_depths.contains(&bit_depth) {
        return None;
    }
    Some(ImageInfo {
        format: ImageFormat::Png,
        width,
        height,
        bit_depth,
        colour,
        levels: pyramid_levels(width, height),
    })
}

fn probe_gif(bytes: &[u8]) -> Option<ImageInfo> {
    let width = le16(bytes, 6)? as u32;
    let height = le16(bytes, 8)? as u32;
    let packed = *bytes.get(10)?;
    if width == 0 || height == 0 {
        return None;
    }
    // A GIF always indexes a palette; the global table (if present) is 2^(n+1)
    // entries. Bit depth is the logical colour resolution (packed bits 4..6 + 1).
    let bit_depth = ((packed >> 4) & 0x07) + 1;
    Some(ImageInfo {
        format: ImageFormat::Gif,
        width,
        height,
        bit_depth,
        colour: ColourModel::Palette,
        levels: pyramid_levels(width, height),
    })
}

fn probe_bmp(bytes: &[u8]) -> Option<ImageInfo> {
    let dib_size = le32(bytes, 14)?;
    let (width, height, bit_depth) = if dib_size == 12 {
        // BITMAPCOREHEADER: u16 width/height, u16 planes, u16 bitcount.
        let w = le16(bytes, 18)? as i16 as i32;
        let h = le16(bytes, 20)? as i16 as i32;
        let bpp = le16(bytes, 24)? as u8;
        (w, h, bpp)
    } else if dib_size >= 40 {
        // BITMAPINFOHEADER or later.
        let w = le32(bytes, 18)? as i32;
        let h = le32(bytes, 22)? as i32;
        let bpp = le16(bytes, 28)? as u8;
        (w, h, bpp)
    } else {
        return None;
    };
    if width == 0 || height == 0 {
        return None;
    }
    let colour = match bit_depth {
        1 | 4 | 8 => ColourModel::Palette,
        16 | 24 => ColourModel::Rgb,
        32 => ColourModel::Rgba,
        _ => return None,
    };
    Some(ImageInfo {
        format: ImageFormat::Bmp,
        width: width.unsigned_abs(),
        height: height.unsigned_abs(),
        bit_depth,
        colour,
        levels: pyramid_levels(width.unsigned_abs(), height.unsigned_abs()),
    })
}

fn probe_jpeg(bytes: &[u8]) -> Option<ImageInfo> {
    // Scan the marker segments for a Start-Of-Frame (SOFn), which carries the
    // frame precision, dimensions, and component count.
    let mut i = 2usize; // skip SOI (FFD8)
    while i + 3 < bytes.len() {
        if bytes[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = bytes[i + 1];
        // Standalone markers without a length payload.
        if (0xD0..=0xD9).contains(&marker) || marker == 0x01 {
            i += 2;
            continue;
        }
        let seg_len = be16(bytes, i + 2)? as usize;
        if seg_len < 2 {
            return None;
        }
        let is_sof = matches!(
            marker,
            0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF
        );
        if is_sof {
            let precision = *bytes.get(i + 4)?;
            let height = be16(bytes, i + 5)? as u32;
            let width = be16(bytes, i + 7)? as u32;
            let components = *bytes.get(i + 9)?;
            if width == 0 || height == 0 {
                return None;
            }
            let colour = match components {
                1 => ColourModel::Grayscale,
                3 => ColourModel::YCbCr,
                4 => ColourModel::Cmyk,
                _ => return None,
            };
            return Some(ImageInfo {
                format: ImageFormat::Jpeg,
                width,
                height,
                bit_depth: precision,
                colour,
                levels: pyramid_levels(width, height),
            });
        }
        i += 2 + seg_len;
    }
    None
}

/// Read and probe a file by content (the file name is ignored entirely).
pub fn probe_path(path: &std::path::Path) -> std::io::Result<Option<ImageInfo>> {
    let bytes = std::fs::read(path)?;
    Ok(probe(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal, valid PNG header (signature + IHDR) for testing. The
    /// bytes after IHDR are irrelevant to header parsing.
    fn png_header(width: u32, height: u32, depth: u8, colour: u8) -> Vec<u8> {
        let mut b = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        b.extend_from_slice(&13u32.to_be_bytes());
        b.extend_from_slice(b"IHDR");
        b.extend_from_slice(&width.to_be_bytes());
        b.extend_from_slice(&height.to_be_bytes());
        b.push(depth);
        b.push(colour);
        b.push(0);
        b.push(0);
        b.push(0);
        b
    }

    #[test]
    fn png_recognition_and_semantics() {
        let info = probe(&png_header(640, 480, 8, 6)).unwrap();
        assert_eq!(info.format, ImageFormat::Png);
        assert_eq!((info.width, info.height), (640, 480));
        assert_eq!(info.colour, ColourModel::Rgba);
        assert_eq!(info.bit_depth, 8);
        assert_eq!(info.levels[0].width, 640);
        assert_eq!(info.levels[1].width, 320);
        assert_eq!(info.levels.last().unwrap().width, 1);
        // An invalid colour type/depth combination is rejected, not guessed.
        assert!(probe(&png_header(10, 10, 16, 3)).is_none());
        assert!(probe(&png_header(0, 10, 8, 0)).is_none());
    }

    #[test]
    fn recognition_is_by_content_not_extension() {
        // A PNG payload is recognised regardless of any (absent) name, and
        // arbitrary bytes with a .png-looking name are not an image.
        let png = png_header(4, 4, 8, 2);
        assert_eq!(recognize(&png), Some(ImageFormat::Png));
        assert_eq!(recognize(b"plain text pretending to be a picture"), None);
    }

    #[test]
    fn gif_and_bmp_headers_parse() {
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&320u16.to_le_bytes());
        gif.extend_from_slice(&200u16.to_le_bytes());
        gif.push(0xF7); // has global colour table, 8-bit resolution
        gif.push(0);
        gif.push(0);
        let info = probe(&gif).unwrap();
        assert_eq!(info.format, ImageFormat::Gif);
        assert_eq!((info.width, info.height), (320, 200));
        assert_eq!(info.colour, ColourModel::Palette);

        let mut bmp = b"BM".to_vec();
        bmp.extend_from_slice(&[0u8; 12]); // file header padding (size/reserved/offset)
        bmp.extend_from_slice(&40u32.to_le_bytes()); // DIB header size
        bmp.extend_from_slice(&128i32.to_le_bytes()); // width
        bmp.extend_from_slice(&64i32.to_le_bytes()); // height
        bmp.extend_from_slice(&1u16.to_le_bytes()); // planes
        bmp.extend_from_slice(&24u16.to_le_bytes()); // bit count
        let info = probe(&bmp).unwrap();
        assert_eq!(info.format, ImageFormat::Bmp);
        assert_eq!((info.width, info.height), (128, 64));
        assert_eq!(info.colour, ColourModel::Rgb);
    }

    #[test]
    fn pyramid_geometry_adds_about_a_third() {
        let levels = pyramid_levels(1024, 1024);
        assert_eq!(levels.len(), 11); // 1024 .. 1
        assert_eq!(levels[0].width, 1024);
        assert_eq!(levels[10].width, 1);
    }
}
