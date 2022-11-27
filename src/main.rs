use std::{env, fs::File, io::Write, path::Path};

use glob::glob;
use image::{io::Reader, EncodableLayout, ImageBuffer, Rgba};

struct ProgramArguments {
    pub is_palette_build_palette: bool,
    pub glob: String,
    pub palette_filename: Option<String>,
}

impl ProgramArguments {
    fn new(args: Vec<String>) -> Self {
        if args.len() == 1 {
            return Self {
                is_palette_build_palette: false,
                glob: args[0].clone(),
                palette_filename: None,
            };
        }
        if args[0].eq("--palette") {
            return Self {
                is_palette_build_palette: true,
                glob: args[1].clone(),
                palette_filename: None,
            };
        }
        if args[1].eq("--palette") {
            return Self {
                is_palette_build_palette: true,
                glob: args[0].clone(),
                palette_filename: None,
            };
        }
        return Self {
            is_palette_build_palette: false,
            glob: args[0].clone(),
            palette_filename: args.get(1).map(|v| String::from(v.as_str())),
        };
    }
}

fn pixel_to_u32(px: &Rgba<u8>) -> u32 {
    return (px.0[0] as u32) << 24
        | (px.0[1] as u32) << 16
        | (px.0[2] as u32) << 8
        | px.0[3] as u32;
}

fn u32_to_u8_buff(px: u32) -> [u8; 4] {
    return [
        ((px & 0xFF00_0000) >> 24) as u8,
        ((px & 0x00FF_0000) >> 16) as u8,
        ((px & 0x0000_FF00) >> 8) as u8,
        (px & 0x0000_00FF) as u8,
    ];
}

fn process_palette(img: &ImageBuffer<Rgba<u8>, Vec<u8>>) -> Vec<u32> {
    let mut palette = Vec::new();
    for x in 0..img.width() {
        for y in 0..img.height() {
            let pixel = pixel_to_u32(img.get_pixel(x, y));
            if !palette.contains(&pixel) {
                palette.push(pixel);
            }
        }
    }
    return palette;
}

fn save_palette(path: &Path, palette: &Vec<u32>) {
    let mut new_path = String::from(path.as_os_str().to_str().unwrap());
    new_path.push_str(".bin");
    let file_result = File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(Path::new(new_path.as_str()));
    match file_result {
        Err(error) => println!("Could not create file {:?}", error),
        Ok(mut file) => palette.into_iter().for_each(|px| {
            file.write(&u32_to_u8_buff(*px))
                .expect("Did not write bytes");
        }),
    }
}

fn save_bytes(path: &Path, bytes: Vec<u8>) {
    let mut new_path = String::from(path.as_os_str().to_str().unwrap());
    new_path.push_str(".bin");
    let file_result = File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(Path::new(new_path.as_str()));
    match file_result {
        Err(error) => println!("Could not create file {:?}", error),
        Ok(mut file) => {
            file.write(bytes.as_bytes()).expect("Did not write bytes");
        }
    }
}

fn index_to_color_index(
    img: &ImageBuffer<Rgba<u8>, Vec<u8>>,
    palette: &Vec<u32>,
    index: u32,
) -> u8 {
    let pixel = pixel_to_u32(img.get_pixel(index % img.width(), index / img.width()));
    let color_index = palette
        .iter()
        .position(|&v| v == pixel)
        .or(Some(0))
        .unwrap();
    let byte_offset = (3 - index % 4) * 2;
    return ((color_index & 0x03) << byte_offset) as u8;
}

fn img_to_bytes(img: &ImageBuffer<Rgba<u8>, Vec<u8>>, palette: &Vec<u32>) -> Vec<u8> {
    let buff_size = img.width() * img.height() / 4;
    let mut bytes = vec![0; buff_size as usize];
    for i in 0..buff_size {
        let offset = i * 4;
        bytes[i as usize] = index_to_color_index(img, palette, offset)
            | index_to_color_index(img, palette, offset + 1)
            | index_to_color_index(img, palette, offset + 2)
            | index_to_color_index(img, palette, offset + 3)
    }

    return bytes;
}

fn process_png_palette(path: &Path, img: &ImageBuffer<Rgba<u8>, Vec<u8>>) {
    let palette = process_palette(&img);
    if palette.len() != 4 {
        println!(
            "{} must contain exactly 4 colors, skipped.",
            path.as_os_str().to_str().unwrap()
        )
    }
    save_palette(path, &palette);
}

fn process_png(path: &Path, is_palette_build: bool, default_palette: &Option<Vec<u32>>) {
    let img = Reader::open(path).unwrap().decode().unwrap().to_rgba8();
    if is_palette_build || String::from(path.as_os_str().to_str().unwrap()).ends_with(".pal.png") {
        return process_png_palette(path, &img);
    }
    let palette = match default_palette {
        None => process_palette(&img),
        Some(data) => data.to_vec(),
    };
    if palette.len() > 4 {
        println!(
            "Warning: palette has a size of {} which is greater than 4",
            palette.len()
        )
    }
    let bytes = img_to_bytes(&img, &palette);
    save_bytes(path, bytes);
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    args.remove(0);
    if args.len() < 1
        || args.len() > 3
        || args.contains(&String::from("-h"))
        || args.contains(&String::from("--help"))
    {
        println!("Usage: png-to-2bits [--palette] filename_or_glob [palette_filename]");
        println!("  --palette : Make the program process filename_or_glob as palette files, palette_filename will be ignored");
        println!("  palette_filename: specify the palette_filename (.png) to use for all filename_or_glob file so the index remain consistent across files");
        return;
    }
    let program_arguments = ProgramArguments::new(args);
    let default_palette = match program_arguments.palette_filename {
        None => None,
        Some(filename) => Some(process_palette(
            &Reader::open(filename).unwrap().decode().unwrap().to_rgba8(),
        )),
    };

    for entry in glob(program_arguments.glob.as_str()).unwrap() {
        match entry {
            Ok(filename) => process_png(
                filename.as_path(),
                program_arguments.is_palette_build_palette,
                &default_palette,
            ),
            Err(error) => println!("Error: {:?}", error),
        }
    }
}
