// Don't open a console window on Windows for release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    achilles_lib::run()
}
