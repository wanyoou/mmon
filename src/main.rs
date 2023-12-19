#![allow(non_snake_case)]

use config::Config;
use log::{error, info};
use log4rs;
use regex::Regex;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::VecDeque;
use std::sync::{
    mpsc::{self, Receiver, Sender},
    Mutex,
};
use std::thread;
use std::time::{Duration, Instant};
use windows::{
    Win32::Foundation::{GetLastError, HWND, LPARAM, LRESULT, WPARAM},
    Win32::System::LibraryLoader::GetModuleHandleW,
    Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, GetMessageW, SetWindowsHookExW, UnhookWindowsHookEx, HC_ACTION, HHOOK,
        KBDLLHOOKSTRUCT, MSG, WH_KEYBOARD_LL, WM_KEYDOWN,
    },
};

const CONFIG_FILE: &str = "config/config.toml";
const LOG_CONFIG_FILE: &str = "config/log4rs.yaml";

lazy_static::lazy_static! {
    static ref CONFIG: MonitorConfig = MonitorConfig::new(CONFIG_FILE);
    static ref TIME_THRESHOLD_RAW: u64 = CONFIG.time_threshold.unwrap();
    static ref TIME_THRESHOLD: Duration = Duration::from_millis(*TIME_THRESHOLD_RAW);
    static ref CLIENT_SN: String = CONFIG.client_sn.clone().unwrap();
    static ref SERVER_URL: String = CONFIG.server_url.clone().unwrap();
    static ref REGEX_RAW: String = CONFIG.regex.clone().unwrap();
    static ref REGEX_PATTERN: Regex = Regex::new((*REGEX_RAW).as_str()).unwrap();
    static ref MODE: MonitorMode = CONFIG.mode.clone().unwrap();
    static ref INPUT_STATE: Mutex<VecDeque<InputState>> = Mutex::new(VecDeque::with_capacity(20));
}
static mut TX: Option<&mut Sender<String>> = None;

struct InputState {
    buffer: String,
    start_time: Instant,
}

#[derive(Deserialize, Clone, Debug)]
enum MonitorMode {
    Block,       // 屏蔽
    Passthrough, // 透传
}

#[derive(Deserialize, Clone, Debug)]
struct MonitorConfig {
    server_url: Option<String>,  // 后台接口地址
    regex: Option<String>,       // 匹配正则
    client_sn: Option<String>,   // 客户端序列号
    time_threshold: Option<u64>, // 时间阈值, ms
    mode: Option<MonitorMode>,   // 监控模式
}

impl MonitorConfig {
    fn new(path: &str) -> MonitorConfig {
        Config::builder()
            .add_source(config::File::with_name(path))
            .build()
            .unwrap()
            .try_deserialize::<MonitorConfig>()
            .expect("Failed to load config")
    }
}

/**
 * 每触发一次击键事件，就依次检查已经存在的实例是否超时。
 * 如果实例超时，就删除超时实例；否则更新实例 buffer，同时检查是否可以成功匹配。
 * 如果有实例成功匹配，就清空实例队列，删除所有实例；否则新创建一个 InputState 实例。
 */
unsafe extern "system" fn keyboard_proc(n_code: i32, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    if (n_code as u32 == HC_ACTION) && (w_param.0 as u32 == WM_KEYDOWN) {
        let kb_struct = *(l_param.0 as *const KBDLLHOOKSTRUCT);
        let key = kb_struct.vkCode as u8 as char;
        let mut input_state = INPUT_STATE.lock().unwrap();

        // 是否已经创建了新实例
        let mut new_instance = false;
        if input_state.is_empty() {
            input_state.push_back(InputState {
                buffer: String::new(),
                start_time: Instant::now(),
            });
            new_instance = true;
        }

        let mut timeout_count = 0;
        let mut match_success = false;
        for input in input_state.iter_mut() {
            if input.start_time.elapsed() > *TIME_THRESHOLD {
                timeout_count += 1;
            } else {
                input.buffer.push(key);
                if REGEX_PATTERN.is_match(&input.buffer) {
                    let input_valid = input.buffer.trim_end();
                    info!("检测到有效的扫码枪输入: {}", input_valid);
                    TX.as_ref().unwrap().send(input_valid.to_string()).unwrap();
                    match_success = true;
                    break;
                }
            }
        }

        if match_success {
            input_state.clear();
        } else if !new_instance {
            // 新创建一个实例，排除第一个实例刚刚创建过的情况
            input_state.push_back(InputState {
                buffer: key.to_string(),
                start_time: Instant::now(),
            })
        }

        // 删除超时实例
        if !match_success && timeout_count > 0 {
            while timeout_count > 0 {
                input_state.pop_front();
                timeout_count -= 1;
            }
        }
    }

    if let MonitorMode::Passthrough = *MODE {
        CallNextHookEx(HHOOK(0), n_code, w_param, l_param)
    } else {
        LRESULT(0)
    }
}

fn log_init() {
    log4rs::init_file(LOG_CONFIG_FILE, Default::default()).unwrap();
    info!("Barcode Scanner Monitor 程序初始化");
    info!("客户端序列号: {}", *CLIENT_SN);
    info!("监控模式: {:?}", *MODE);
    info!("正则表达式: {}", *REGEX_RAW);
    info!("扫码枪时间阈值: {}ms", *TIME_THRESHOLD_RAW);
    info!("后台接口地址: {}", *SERVER_URL);
    info!("Barcode Scanner Monitor 程序初始化完成");
}

fn main() -> windows::core::Result<()> {
    log_init();

    let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();
    unsafe {
        TX = Some(Box::leak(Box::new(tx)));
    }

    thread::spawn(move || -> reqwest::Result<()> {
        let mut req;
        let mut res;
        let client = Client::new();
        while let Ok(value) = rx.recv() {
            req = client
                .get((*SERVER_URL).as_str())
                .query(&[("code", value.as_str()), ("sn", (*CLIENT_SN).as_str())])
                .timeout(Duration::from_secs(3));
            info!("GET Request: {:?}", req);

            res = req.send()?;
            if res.status().is_success() {
                info!("GET Response: {}", res.text()?);
            } else {
                error!("GET Response Error. Status: {:?}", res.status());
            }
        }
        Ok(())
    });

    unsafe {
        let h_instance = GetModuleHandleW(None).unwrap();
        let hook_id =
            SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_proc), h_instance, 0).unwrap();

        if hook_id.is_invalid() {
            eprintln!("Failed to install hook: {:?}", GetLastError());
            return Err(windows::core::Error::from_win32());
        }

        let mut msg: MSG = MSG::default();
        while GetMessageW(&mut msg, HWND(0), 0, 0).into() {
            // Block here until a message is received
        }

        let _ = UnhookWindowsHookEx(hook_id);
    }

    Ok(())
}
