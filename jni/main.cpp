#include <unistd.h>
#include <android/log.h>
#include <dlfcn.h>
#include <string>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <thread>
#include <regex>
#include <chrono>
#include "frida-gum.h"

#define LOG_TAG "FridaGum"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// ⏱️ 计时器类 - 用于性能分析
class Timer {
private:
    std::chrono::high_resolution_clock::time_point start_time;
    const char* name;
    
public:
    Timer(const char* operation_name) : name(operation_name) {
        start_time = std::chrono::high_resolution_clock::now();
    }
    
    ~Timer() {
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        LOGI("⏱️ [%s] 耗时: %lld ms", name, (long long)duration.count());
    }
    
    // 手动输出中间耗时（不销毁计时器）
    void checkpoint(const char* checkpoint_name) {
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
        LOGI("⏱️ [%s -> %s] 耗时: %lld ms", name, checkpoint_name, (long long)duration.count());
    }
};


// 游戏引擎类型
enum class GameEngine {
    UNKNOWN,
    UNITY,
    UNREAL,
    COCOS2D_CPP,   // Cocos2d-x (C++ 版本)
    COCOS2D_JS,    // Cocos2d-js (JavaScript 版本)
    GODOT
};

// 库信息映射表
using LibraryMap = std::unordered_map<std::string, std::string>;

// 从路径中提取库名称
std::string extractLibraryName(const std::string& path) {
    size_t last_slash = path.rfind('/');
    if (last_slash == std::string::npos) return path;
    return path.substr(last_slash + 1);
}

// 读取 /proc/self/maps 获取私有库映射
LibraryMap parseMaps() {
    Timer timer("parseMaps");  // ⏱️ 计时开始
    LibraryMap library_map;
    std::ifstream maps_file("/proc/self/maps");
    
    if (!maps_file.is_open()) {
        LOGE("无法打开 /proc/self/maps");
        return library_map;
    }
    
    std::string line;
    while (std::getline(maps_file, line)) {
        // 查找包含 data/app 或 data/data 的路径
        if (line.find("data/") != std::string::npos  ) {
            
            // maps 格式：address perms offset dev inode pathname
            size_t path_start = line.rfind(' ');
            if (path_start != std::string::npos) {
                std::string full_path = line.substr(path_start + 1);
                
                // 提取库名称
                std::string lib_name = extractLibraryName(full_path);
                
                // 记录 .so 文件和 base.apk
                if (lib_name.find(".so") != std::string::npos || 
                    lib_name.find("base.apk") != std::string::npos) {
                    library_map[lib_name] = full_path;
                }
            }
        }
    }
    
    maps_file.close();
    LOGI("解析 maps，共找到 %zu 个私有库", library_map.size());
    return library_map;
}

// 从路径中提取包名
std::string extractPackageName(const std::string& path) {
    // 格式1：/data/data/com.game.pkg/files/libcpp_shared.so
    //        提取：com.game.pkg
    // 格式2：/data/app/~~xxx/com.sqw.jwdzg.jwdzg_ptzy-xxx==/lib/arm64/libcpp_shared.so
    //        提取：com.sqw.jwdzg.jwdzg_ptzy
 
    // 尝试格式1：/data/data/包名/files/...
    // ✅ 优化：通过 /files/ 定位，向前提取包名
    size_t files_pos = path.find("/files/");
    if (files_pos != std::string::npos) {
        // files_pos 本身就是 /files/ 前面的 '/'
        size_t pkg_end = files_pos;
        
        // 向前找到包名起始位置的 '/'（/data/data/ 后面）
        size_t pkg_start = path.rfind('/', pkg_end - 1);
        if (pkg_start != std::string::npos) {
            std::string package_name = path.substr(pkg_start + 1, pkg_end - pkg_start - 1);
            
            // 验证是否为有效包名（至少包含一个点）
            if (package_name.find('.') != std::string::npos) {
                return package_name;
            }
        }
    }
    
    // 尝试格式2和格式3：/data/app/ 路径
    // 格式2：/data/app/~~xxx/包名-xxx==/
    // 格式3：/data/app/包名-xxx==/（直接包名，无 ~~xxx/ 前缀）
    // /data/app/bin.mt.plus-1/base.apk
    size_t data_pos = path.find("/data/app/");
    if (data_pos != std::string::npos) {
        // ✅ 一步式实现：先切割再提取 (getgamepkg 方式)
        // 1. 找到最后一个 '-' 并截取之前的部分
        std::string beforeDash = path.substr(0, path.find_last_of('-'));
        
        // 2. 找到最后一个 '/' 并提取包名部分
        size_t lastSlash = beforeDash.find_last_of('/');
        if (lastSlash != std::string::npos) {
            std::string tpkg = beforeDash.substr(lastSlash + 1);
            
            // 3. 再次去除第一个 '-' 后的内容（去除包名中的版本后缀）
            std::string package_name = tpkg.substr(0, tpkg.find("-"));
            
            // 验证是否为有效包名（至少包含一个点）
            if (package_name.find('.') != std::string::npos) {
                return package_name;
            }
        }
    }
    
    return "";
}

// 根据包名查找 base.apk 路径
std::string findBaseApkPath(const LibraryMap& library_map, const std::string& package_name) {
    Timer timer("findBaseApkPath");  // ⏱️ 计时开始
    if (package_name.empty()) return "";
    
    LOGI("开始查找包含 '%s' 和 'base.apk' 的路径", package_name.c_str());
    
    // ✅ 优化：使用正则表达式匹配路径（格式：.../包名.../base.apk...）
    std::string pattern_str = ".*" + package_name + ".*base\\.apk";
    std::regex apk_pattern(pattern_str);
    
    for (const auto& [lib_name, lib_path] : library_map) {
        // 使用正则表达式一次性匹配包名和 base.apk
        std::smatch match;
        if (std::regex_search(lib_path, match, apk_pattern)) {
            LOGI("找到匹配路径: %s", lib_path.c_str());
            
            // 提取 base.apk 路径（截断到 base.apk）
            size_t apk_pos = lib_path.find("base.apk");
            if (apk_pos != std::string::npos) {
                std::string result = lib_path.substr(0, apk_pos + std::strlen("base.apk"));
                LOGI("✓ APK 路径: %s", result.c_str());
                return result;
            }
        }
    }
    
    return "";
}

// 结构体：库文件信息
struct LibraryInfo {
    std::string name;
    size_t size;
};

// 执行命令并获取输出
std::string executeCommand(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        LOGE("命令执行失败: %s", cmd.c_str());
        return "";
    }
    
    std::stringstream result;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result << buffer;
    }
    
    pclose(pipe);
    return result.str();
}

// 解析 ls -l 输出，找到最大的库
std::string findLargestLibrary(const std::string& lib_dir) {
    Timer timer("findLargestLibrary");  // ⏱️ 计时开始
    // 执行命令：ls -l | grep -v ^total
    std::string cmd = "ls -l " + lib_dir + " | grep -v ^total";
    std::string output = executeCommand(cmd);
    
    if (output.empty()) {
        LOGE("库目录为空或命令执行失败: %s", lib_dir.c_str());
        return "";
    }
    
    // LOGI("ls -l 输出:\n%s", output.c_str());
    
    std::vector<LibraryInfo> libraries;
    std::istringstream stream(output);
    std::string line;
    
    // 正则表达式：匹配文件大小和 .so 文件名
    // 格式：... size ... datetime filename.so
    std::regex pattern(R"(\s+(\d+)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+(\S+\.so))");
    
    // 解析每一行
    while (std::getline(stream, line)) {
        // 跳过空行
        if (line.empty() || line.find_first_not_of(" \t\r\n") == std::string::npos) {
            continue;
        }
        
        std::smatch match;
        if (std::regex_search(line, match, pattern)) {
            // match[1] = 文件大小
            // match[2] = 文件名
            std::string size_str = match[1].str();
            std::string filename = match[2].str();
            
            char* endptr = nullptr;
            unsigned long long size = strtoull(size_str.c_str(), &endptr, 10);
            
            if (endptr != size_str.c_str() && *endptr == '\0') {
                libraries.push_back({filename, static_cast<size_t>(size)});
                LOGI("✓ 发现库: %s (大小: %zu 字节)", filename.c_str(), static_cast<size_t>(size));
            } else {
                LOGE("✗ 解析文件大小失败: size_str='%s'", size_str.c_str());
            }
        } else {
            LOGI("⊘ 正则不匹配: %s", line.c_str());
        }
    }
    
    if (libraries.empty()) {
        LOGE("未找到任何 .so 库文件");
        return "";
    }
    
    // 找到最大的库
    auto largest = std::max_element(libraries.begin(), libraries.end(),
        [](const LibraryInfo& a, const LibraryInfo& b) {
            return a.size < b.size;
        });
    
    LOGI("最大库: %s (大小: %zu 字节)", largest->name.c_str(), largest->size);
    return largest->name;
}

// 识别游戏引擎
GameEngine identifyGameEngine(GumModule* module) {
    Timer timer("identifyGameEngine");  // ⏱️ 计时开始
    const gchar* module_name = gum_module_get_name(module);
    std::string lower_name = module_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    if (lower_name.find("il2cpp") != std::string::npos || 
        lower_name.find("unity") != std::string::npos) {
        return GameEngine::UNITY;
    }
    
    if (lower_name.find("ue4") != std::string::npos || 
        lower_name.find("ue5") != std::string::npos ||
        lower_name.find("unreal") != std::string::npos) {
        return GameEngine::UNREAL;
    }
    
    // ✅ 优化：通过文件名直接区分 Cocos2d-js 和 Cocos2d-x (C++)
    // 避免两次耗时的符号枚举（从 500ms 降低到 < 1ms）
    if (lower_name.find("cocos") != std::string::npos) {
        // libcocos.so 和 libcocos2djs.so 归类为 Cocos2d-js
        if (lower_name == "libcocos.so" || lower_name == "libcocos2djs.so") {
            LOGI("根据文件名识别为 Cocos2d-js: %s", module_name);
            return GameEngine::COCOS2D_JS;
        }
        
        // 其他 cocos 相关库归类为 Cocos2d-x (C++)
        LOGI("根据文件名识别为 Cocos2d-x (C++): %s", module_name);
        return GameEngine::COCOS2D_CPP;
    }
    
    if (lower_name.find("godot") != std::string::npos) {
        return GameEngine::GODOT;
    }
    
    return GameEngine::UNKNOWN;
}

// 获取引擎名称
const char* getEngineName(GameEngine engine) {
    switch (engine) {
        case GameEngine::UNITY: return "Unity";
        case GameEngine::UNREAL: return "Unreal Engine";
        case GameEngine::COCOS2D_CPP: return "Cocos2d-x (C++)";
        case GameEngine::COCOS2D_JS: return "Cocos2d-js (JavaScript)";
        case GameEngine::GODOT: return "Godot";
        default: return "Unknown";
    }
}

// 全局加速倍率
static float g_speed_multiplier = 4.0f;

// Cocos2d-js 相关全局变量
static int mycount = 100;                  // JS 调用计数器
static std::string g_pkg;                // 全局包名

// JSON 对象指针 → 原始字符串 映射表
static std::unordered_map<void*, std::string> g_json_string_map;

// 最近的 JSON 字符串缓存（简单方案）
static std::string g_last_json_string;

// libcocos2dcpp.so 基址（用于访问全局变量）
static GumAddress g_cocos2d_base_addr = 0;

// 请求缓存结构
struct CachedRequest {
    int request_id;
    int operation_type;
    int a4, a5, a6, a7, a8;
    std::string param1;
    std::string param2;
    std::string param3;
    bool record_time;
};

// 获取请求缓存文件路径
std::string getRequestCachePath(int request_id) {
    return std::string("/sdcard/Android/data/") + g_pkg + "/cache/request_" + 
           std::to_string(request_id) + ".cache";
}

// 获取 Money/Gold 修改状态文件路径
std::string getModifiedStatePath() {
    return std::string("/sdcard/Android/data/") + g_pkg + "/cache/currency_modified.state";
}

// 检查 Money/Gold 是否已经被修改过
bool isCurrencyModified() {
    std::string state_path = getModifiedStatePath();
    std::ifstream state_file(state_path);
    
    if (!state_file.is_open()) {
        return false;  // 文件不存在，说明还没修改过
    }
    
    std::string line;
    bool money_modified = false;
    bool gold_modified = false;
    
    while (std::getline(state_file, line)) {
        if (line.find("money=1") != std::string::npos) {
            money_modified = true;
        }
        if (line.find("gold=1") != std::string::npos) {
            gold_modified = true;
        }
    }
    
    state_file.close();
    
    // 只有两个都修改过才返回 true
    return money_modified && gold_modified;
}

// 标记 Money 已修改
void markMoneyModified() {
    std::string state_path = getModifiedStatePath();
    
    // 读取现有状态
    std::string content;
    std::ifstream in(state_path);
    bool gold_already_marked = false;
    
    if (in.is_open()) {
        std::string line;
        while (std::getline(in, line)) {
            if (line.find("gold=1") != std::string::npos) {
                gold_already_marked = true;
            }
        }
        in.close();
    }
    
    // 重新写入
    std::ofstream out(state_path);
    if (out.is_open()) {
        out << "money=1\n";
        if (gold_already_marked) {
            out << "gold=1\n";
        }
        out.close();
        LOGI("✅ 已标记 Money 为已修改");
    }
}

// 标记 Gold 已修改
void markGoldModified() {
    std::string state_path = getModifiedStatePath();
    
    // 读取现有状态
    std::string content;
    std::ifstream in(state_path);
    bool money_already_marked = false;
    
    if (in.is_open()) {
        std::string line;
        while (std::getline(in, line)) {
            if (line.find("money=1") != std::string::npos) {
                money_already_marked = true;
            }
        }
        in.close();
    }
    
    // 重新写入
    std::ofstream out(state_path);
    if (out.is_open()) {
        if (money_already_marked) {
            out << "money=1\n";
        }
        out << "gold=1\n";
        out.close();
        LOGI("✅ 已标记 Gold 为已修改");
    }
}

// 保存请求到文件
void saveRequestToFile(int request_id, const CachedRequest& req) {
    std::string cache_path = getRequestCachePath(request_id);
    std::ofstream out(cache_path, std::ios::binary);
    
    if (!out.is_open()) {
        LOGE("❌ 无法创建缓存文件: %s", cache_path.c_str());
        return;
    }
    
    // 写入请求信息（简单格式）
    out << req.request_id << "\n";
    out << req.operation_type << "\n";
    out << req.a4 << "\n";
    out << req.a5 << "\n";
    out << req.a6 << "\n";
    out << req.a7 << "\n";
    out << req.a8 << "\n";
    out << (req.record_time ? 1 : 0) << "\n";
    
    // 写入字符串长度和内容
    out << req.param1.length() << "\n";
    if (!req.param1.empty()) {
        out << req.param1 << "\n";
    }
    
    out << req.param2.length() << "\n";
    if (!req.param2.empty()) {
        out << req.param2 << "\n";
    }
    
    out << req.param3.length() << "\n";
    if (!req.param3.empty()) {
        out << req.param3 << "\n";
    }
    
    out.close();
    LOGI("✅ 请求已保存到文件: %s", cache_path.c_str());
}

// 从文件读取请求
bool loadRequestFromFile(int request_id, CachedRequest& req) {
    std::string cache_path = getRequestCachePath(request_id);
    std::ifstream in(cache_path, std::ios::binary);
    
    if (!in.is_open()) {
        LOGD("ℹ️ 缓存文件不存在: %s", cache_path.c_str());
        return false;
    }
    
    // 读取请求信息
    if (!(in >> req.request_id)) {
        LOGE("❌ 读取 request_id 失败");
        in.close();
        return false;
    }
    
    in >> req.operation_type;
    in >> req.a4;
    in >> req.a5;
    in >> req.a6;
    in >> req.a7;
    in >> req.a8;
    
    int record_time_int;
    in >> record_time_int;
    req.record_time = (record_time_int != 0);
    
    in.ignore(); // 忽略换行符
    
    // 读取字符串1
    size_t len1;
    in >> len1;
    in.ignore();
    if (len1 > 0 && len1 < 100000) {
        req.param1.resize(len1);
        in.read(&req.param1[0], len1);
        in.ignore();
    } else {
        req.param1.clear();
    }
    
    // 读取字符串2
    size_t len2;
    in >> len2;
    in.ignore();
    if (len2 > 0 && len2 < 100000) {
        req.param2.resize(len2);
        in.read(&req.param2[0], len2);
        in.ignore();
    } else {
        req.param2.clear();
    }
    
    // 读取字符串3
    size_t len3;
    in >> len3;
    in.ignore();
    if (len3 > 0 && len3 < 100000) {
        req.param3.resize(len3);
        in.read(&req.param3[0], len3);
        in.ignore();
    } else {
        req.param3.clear();
    }
    
    in.close();
    LOGI("✅ 从文件加载请求缓存: %s", cache_path.c_str());
    return true;
}

// 符号缓存文件路径
std::string getSymbolCachePath() {
    return std::string("/sdcard/Android/data/") + g_pkg + "/cache/symbols.cache";
}

// 缓存条目类型
enum class CacheType {
    NONE,       // 未找到
    SYMBOL,     // 符号名
    OFFSET      // 内存搜索偏移
};

// 缓存条目结构
struct CacheEntry {
    CacheType type;
    std::string value;  // 符号名 或 偏移量(十六进制字符串)
};

// 从文件读取缓存条目（带类型）
CacheEntry readFromCache(const std::string& cache_key) {
    std::string cache_path = getSymbolCachePath();
    std::ifstream cache_file(cache_path);
    
    if (!cache_file.is_open()) {
        LOGD("符号缓存文件不存在: %s", cache_path.c_str());
        return {CacheType::NONE, ""};
    }
    
    std::string line;
    while (std::getline(cache_file, line)) {
        // 格式：cache_key=type:value
        // 示例：ScriptEngine_evalString=symbol:_ZN2se12ScriptEngine10evalStringE...
        //      或 ScriptEngine_evalString=offset:0xbc8
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string data = line.substr(pos + 1);
            
            if (key == cache_key) {
                // 解析类型和值
                size_t colon_pos = data.find(':');
                if (colon_pos != std::string::npos) {
                    std::string type_str = data.substr(0, colon_pos);
                    std::string value = data.substr(colon_pos + 1);
                    
                    CacheType type = CacheType::NONE;
                    if (type_str == "symbol") {
                        type = CacheType::SYMBOL;
                    } else if (type_str == "offset") {
                        type = CacheType::OFFSET;
                    }
                    
                    cache_file.close();
                    LOGI("✓ 从缓存读取: %s = %s:%s", cache_key.c_str(), type_str.c_str(), value.c_str());
                    return {type, value};
                }
            }
        }
    }
    
    cache_file.close();
    LOGD("缓存中未找到: %s", cache_key.c_str());
    return {CacheType::NONE, ""};
}

// 保存到缓存（带类型）
void saveToCache(const std::string& cache_key, CacheType type, const std::string& value) {
    std::string cache_path = getSymbolCachePath();
    
    // 读取现有缓存
    std::unordered_map<std::string, std::string> symbols;
    std::ifstream cache_file_read(cache_path);
    if (cache_file_read.is_open()) {
        std::string line;
        while (std::getline(cache_file_read, line)) {
            size_t pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string data = line.substr(pos + 1);
                symbols[key] = data;
            }
        }
        cache_file_read.close();
    }
    
    // 构造数据（type:value）
    std::string type_str = (type == CacheType::SYMBOL) ? "symbol" : "offset";
    std::string data = type_str + ":" + value;
    symbols[cache_key] = data;
    
    // 写回文件
    std::ofstream cache_file_write(cache_path);
    if (!cache_file_write.is_open()) {
        LOGE("无法写入符号缓存文件: %s", cache_path.c_str());
        return;
    }
    
    for (const auto& [key, val] : symbols) {
        cache_file_write << key << "=" << val << std::endl;
    }
    
    cache_file_write.close();
    LOGI("✓ 保存到缓存: %s = %s:%s", cache_key.c_str(), type_str.c_str(), value.c_str());
}

// 兼容旧接口（仅用于符号名）
std::string readSymbolNameFromCache(const std::string& cache_key) {
    CacheEntry entry = readFromCache(cache_key);
    if (entry.type == CacheType::SYMBOL) {
        return entry.value;
    }
    return "";
}

// 兼容旧接口（仅用于符号名）
void saveSymbolNameToCache(const std::string& cache_key, const std::string& symbol_name) {
    saveToCache(cache_key, CacheType::SYMBOL, symbol_name);
}

// ============================
// 网络 Hook 相关
// ============================

// CurlHttp::sendData 函数指针
// 函数签名：CurlHttp::sendData(this, a2, a3, a4, a5, a6, a7, a8, *a9, *a10, *a11, a12)
typedef void* (*SendDataFunc)(
    void* curl_http,    // this 指针
    int a2,             // 请求类型ID
    int a3,             // 操作类型
    int a4, int a5, int a6, int a7, int a8,  // 业务参数
    char* a9,           // 参数字符串1
    char* a10,          // 参数字符串2
    char* a11,          // 参数字符串3
    bool a12            // 是否记录时间戳
);
static SendDataFunc original_sendData = nullptr;

// CurlHttp::onHttpRequestCompleted 函数指针
typedef void* (*OnHttpCompletedFunc)(
    void* curl_http,         // this 指针
    void* http_client,       // cocos2d::network::HttpClient*
    void* http_response      // cocos2d::network::HttpResponse*
);
static OnHttpCompletedFunc original_onHttpCompleted = nullptr;

// CurlHttp::parseJson 函数指针
typedef void* (*ParseJsonFunc)(
    void* curl_http,    // this 指针 (实际是 unsigned int*)
    int a2,             // 操作类型ID
    void* json          // JSON对象指针
);
static ParseJsonFunc original_parseJson = nullptr;

// Json_create 函数指针 (0x62ad8c)
typedef void* (*JsonCreateFunc)(const char* json_string);
static JsonCreateFunc original_json_create = nullptr;

// Json_dispose 函数指针
typedef void (*JsonDisposeFunc)(void* json_object);
static JsonDisposeFunc original_json_dispose = nullptr;

// Game_Unpack::updateMoney 函数指针 (0x3880c0)
typedef int64_t (*UpdateMoneyFunc)(void* this_ptr, int add_value, bool save_to_db);
static UpdateMoneyFunc original_updateMoney = nullptr;

// Game_Unpack::updateGold 函数指针 (0x38813c)
typedef int64_t (*UpdateGoldFunc)(void* this_ptr, int add_value, bool save_to_db);
static UpdateGoldFunc original_updateGold = nullptr;

// Hook 后的 updateMoney 函数
static int64_t hooked_updateMoney(void* this_ptr, int add_value, bool save_to_db) {
    // 🔍 检查是否已经修改过
    static bool checked_state = false;
    static bool already_modified = false;
    
    if (!checked_state) {
        already_modified = isCurrencyModified();
        checked_state = true;
        
        if (already_modified) {
            LOGI("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            LOGI("💰 [跳过修改] Money 和 Gold 已在之前修改过");
            LOGI("  将使用正常游戏逻辑，不再进行硬编码");
            LOGI("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        }
    }
    
    // 如果已经修改过，直接调用原始函数
    if (already_modified) {
        return original_updateMoney(this_ptr, add_value, save_to_db);
    }
    
    LOGI("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGI("💰 [修改金币] Game_Unpack::updateMoney");
    LOGI("  this: %p", this_ptr);
    LOGI("  原始增量: %d (0x%x)", add_value, add_value);
    LOGI("  保存到数据库: %s", save_to_db ? "是" : "否");
    
    // 🎯 硬编码目标值
    const int TARGET_MONEY = 0x1123456;  // 17971286
    
    // 获取当前 money 的加密存储地址
    // dword_E2B918 (加密值) 和 dword_E2B91C (密钥)
    static uint32_t* encrypted_money_ptr = nullptr;
    static uint32_t* money_key_ptr = nullptr;
    
    if (!encrypted_money_ptr && g_cocos2d_base_addr != 0) {
        // 通过基址 + 偏移获取全局变量地址
        encrypted_money_ptr = (uint32_t*)(g_cocos2d_base_addr + 0xE2B918);
        money_key_ptr = (uint32_t*)(g_cocos2d_base_addr + 0xE2B91C);
        LOGI("  📍 Money 加密地址: %p", encrypted_money_ptr);
        LOGI("  📍 Money 密钥地址: %p", money_key_ptr);
    }
    
    if (encrypted_money_ptr && money_key_ptr) {
        // 读取当前值
        uint32_t current_encrypted = *encrypted_money_ptr;
        uint32_t current_key = *money_key_ptr;
        int current_money = current_encrypted ^ current_key;
        
        LOGI("  当前金币: %d (0x%x)", current_money, current_money);
        
        // 🔥 强制设置为目标值
        uint32_t new_key = rand();
        *money_key_ptr = new_key;
        *encrypted_money_ptr = TARGET_MONEY ^ new_key;
        
        LOGI("  ✅ 已强制修改为: %d (0x%x)", TARGET_MONEY, TARGET_MONEY);
        LOGI("  新密钥: 0x%x", new_key);
        
        // 标记 Money 已修改
        markMoneyModified();
    } else {
        LOGE("  ❌ 无法获取 Money 全局变量地址");
    }
    
    LOGI("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    // 调用原始函数（但值已被我们修改）
    return original_updateMoney(this_ptr, add_value, save_to_db);
}

// Hook 后的 updateGold 函数
static int64_t hooked_updateGold(void* this_ptr, int add_value, bool save_to_db) {
    // 🔍 检查是否已经修改过
    static bool checked_state = false;
    static bool already_modified = false;
    
    if (!checked_state) {
        already_modified = isCurrencyModified();
        checked_state = true;
        
        if (already_modified) {
            LOGI("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            LOGI("💎 [跳过修改] Money 和 Gold 已在之前修改过");
            LOGI("  将使用正常游戏逻辑，不再进行硬编码");
            LOGI("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        }
    }
    
    // 如果已经修改过，直接调用原始函数
    if (already_modified) {
        return original_updateGold(this_ptr, add_value, save_to_db);
    }
    
    LOGI("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGI("💎 [修改元宝] Game_Unpack::updateGold");
    LOGI("  this: %p", this_ptr);
    LOGI("  原始增量: %d (0x%x)", add_value, add_value);
    LOGI("  保存到数据库: %s", save_to_db ? "是" : "否");
    
    // 🎯 硬编码目标值
    const int TARGET_GOLD = 0x1123456;  // 17971286
    
    // 获取当前 gold 的加密存储地址
    // dword_E2B920 (加密值) 和 dword_E2B924 (密钥)
    static uint32_t* encrypted_gold_ptr = nullptr;
    static uint32_t* gold_key_ptr = nullptr;
    
    if (!encrypted_gold_ptr && g_cocos2d_base_addr != 0) {
        // 通过基址 + 偏移获取全局变量地址
        encrypted_gold_ptr = (uint32_t*)(g_cocos2d_base_addr + 0xE2B920);
        gold_key_ptr = (uint32_t*)(g_cocos2d_base_addr + 0xE2B924);
        LOGI("  📍 Gold 加密地址: %p", encrypted_gold_ptr);
        LOGI("  📍 Gold 密钥地址: %p", gold_key_ptr);
    }
    
    if (encrypted_gold_ptr && gold_key_ptr) {
        // 读取当前值
        uint32_t current_encrypted = *encrypted_gold_ptr;
        uint32_t current_key = *gold_key_ptr;
        int current_gold = current_encrypted ^ current_key;
        
        LOGI("  当前元宝: %d (0x%x)", current_gold, current_gold);
        
        // 🔥 强制设置为目标值
        uint32_t new_key = rand();
        *gold_key_ptr = new_key;
        *encrypted_gold_ptr = TARGET_GOLD ^ new_key;
        
        LOGI("  ✅ 已强制修改为: %d (0x%x)", TARGET_GOLD, TARGET_GOLD);
        LOGI("  新密钥: 0x%x", new_key);
        
        // 标记 Gold 已修改
        markGoldModified();
    } else {
        LOGE("  ❌ 无法获取 Gold 全局变量地址");
    }
    
    LOGI("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    // 调用原始函数（但值已被我们修改）
    return original_updateGold(this_ptr, add_value, save_to_db);
}

// Hook 后的 sendData 函数
static void* hooked_sendData(
    void* curl_http,
    int a2, int a3, int a4, int a5, int a6, int a7, int a8,
    char* a9, char* a10, char* a11, bool a12) {
    
    LOGI("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGI("📤 [网络请求] CurlHttp::sendData");
    LOGI("  this: %p", curl_http);
    LOGI("  请求ID: %d, 操作类型: %d", a2, a3);
    LOGI("  参数: a4=%d, a5=%d, a6=%d, a7=%d, a8=%d", a4, a5, a6, a7, a8);
    
    // 用于存储处理后的参数
    char* final_a9 = a9;
    char* final_a10 = a10;
    char* final_a11 = a11;
    std::string cached_param1, cached_param2, cached_param3;
    bool use_cached = false;
    
    // 检查是否需要缓存（请求ID = 1000）
    if (a2 == 1000) {
        // 检查文件是否已存在
        std::string cache_path = getRequestCachePath(1000);
        std::ifstream check_file(cache_path);
        bool file_exists = check_file.good();
        check_file.close();
        
        if (!file_exists) {
            // 第一次遇到 id=1000 的请求，缓存到文件
            CachedRequest cached;
            cached.request_id = a2;
            cached.operation_type = a3;
            cached.a4 = a4;
            cached.a5 = a5;
            cached.a6 = a6;
            cached.a7 = a7;
            cached.a8 = a8;
            cached.param1 = a9 ? std::string(a9) : "";
            cached.param2 = a10 ? std::string(a10) : "";
            cached.param3 = a11 ? std::string(a11) : "";
            cached.record_time = a12;
            
            saveRequestToFile(1000, cached);
            LOGI("  💾 [已缓存到文件] 首次请求 ID=1000");
        } else {
            // 缓存文件已存在，使用缓存内容替换当前参数
            CachedRequest cached;
            if (loadRequestFromFile(1000, cached)) {
                LOGI("  🔄 [ID=1000] 使用缓存文件内容替换当前参数");
                
                // 保存原始参数用于打印
                std::string original_param1 = a9 ? std::string(a9) : "(null)";
                std::string original_param2 = a10 ? std::string(a10) : "(null)";
                std::string original_param3 = a11 ? std::string(a11) : "(null)";
                
                // 使用缓存的参数
                cached_param1 = cached.param1;
                cached_param2 = cached.param2;
                cached_param3 = cached.param3;
                
                final_a9 = cached_param1.empty() ? nullptr : (char*)cached_param1.c_str();
                final_a10 = cached_param2.empty() ? nullptr : (char*)cached_param2.c_str();
                final_a11 = cached_param3.empty() ? nullptr : (char*)cached_param3.c_str();
                
                use_cached = true;
                
                // 打印对比信息
                LOGI("  📊 参数对比:");
                
                // 字符串1对比
                if (original_param1.length() > 100) {
                    LOGI("    原始字符串1: [长度=%zu] %.100s...", original_param1.length(), original_param1.c_str());
                } else {
                    LOGI("    原始字符串1: %s", original_param1.c_str());
                }
                
                if (cached_param1.length() > 100) {
                    LOGI("    替换字符串1: [长度=%zu] %.100s...", cached_param1.length(), cached_param1.c_str());
                } else {
                    LOGI("    替换字符串1: %s", cached_param1.c_str());
                }
                
                // 字符串2对比
                LOGI("    原始字符串2: %s", original_param2.c_str());
                LOGI("    替换字符串2: %s", cached_param2.empty() ? "(empty)" : cached_param2.c_str());
            } else {
                LOGD("  ⚠️ 缓存文件读取失败，使用原始参数");
            }
        }
    } else {
        // 检查是否为相似请求（包含 uid, money, gold 关键字）
        bool has_key_fields = false;
        if (a9) {
            std::string param1_str(a9);
            if (param1_str.find("uid") != std::string::npos &&
                param1_str.find("money") != std::string::npos &&
                param1_str.find("gold") != std::string::npos) {
                has_key_fields = true;
            }
        }
        
        if (has_key_fields) {
            // 从文件加载缓存的请求
            CachedRequest cached;
            if (loadRequestFromFile(1000, cached)) {
                LOGI("  🔄 [检测到相似请求] 使用缓存文件中的 ID=1000 参数");
                
                // 使用缓存的参数
                cached_param1 = cached.param1;
                cached_param2 = cached.param2;
                cached_param3 = cached.param3;
                
                final_a9 = cached_param1.empty() ? nullptr : (char*)cached_param1.c_str();
                final_a10 = cached_param2.empty() ? nullptr : (char*)cached_param2.c_str();
                final_a11 = cached_param3.empty() ? nullptr : (char*)cached_param3.c_str();
                
                use_cached = true;
                
                LOGI("  ✅ 已替换为文件缓存参数:");
                LOGI("    缓存的请求ID: %d", cached.request_id);
                LOGI("    缓存的操作类型: %d", cached.operation_type);
            } else {
                LOGD("  ⚠️ 未找到缓存文件，使用原始参数");
            }
        }
    }
    
    // 打印将要发送的参数
    if (!use_cached) {
        LOGI("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        LOGI("  📤 将要发送的参数（原始）:");
    }
    
    // 字符串1
    if (final_a9 == nullptr) {
        LOGI("  字符串1: (null)");
    } else {
        size_t len = strnlen(final_a9, 2048);
        if (len == 0) {
            LOGI("  字符串1: (empty)");
        } else if (len >= 2048) {
            LOGI("  字符串1: [长度>=2048] %.500s...", final_a9);
        } else if (len > 500) {
            LOGI("  字符串1: [长度=%zu] %.500s...", len, final_a9);
        } else {
            LOGI("  字符串1: [长度=%zu] %s", len, final_a9);
        }
    }
    
    // 字符串2
    if (final_a10 == nullptr) {
        LOGI("  字符串2: (null)");
    } else {
        size_t len = strnlen(final_a10, 2048);
        if (len == 0) {
            LOGI("  字符串2: (empty)");
        } else if (len >= 2048) {
            LOGI("  字符串2: [长度>=2048] %.500s...", final_a10);
        } else if (len > 500) {
            LOGI("  字符串2: [长度=%zu] %.500s...", len, final_a10);
        } else {
            LOGI("  字符串2: [长度=%zu] %s", len, final_a10);
        }
    }
    
    // 字符串3
    if (final_a11 == nullptr) {
        LOGI("  字符串3: (null)");
    } else {
        size_t len = strnlen(final_a11, 2048);
        if (len == 0) {
            LOGI("  字符串3: (empty)");
        } else if (len >= 2048) {
            LOGI("  字符串3: [长度>=2048] %.500s...", final_a11);
        } else if (len > 500) {
            LOGI("  字符串3: [长度=%zu] %.500s...", len, final_a11);
        } else {
            LOGI("  字符串3: [长度=%zu] %s", len, final_a11);
        }
    }
    
    LOGI("  记录时间: %s", a12 ? "是" : "否");
    
    if (use_cached) {
        LOGI("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        LOGI("  🎯 实际发送: 使用缓存参数（非当前参数）");
        LOGI("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }
    
    LOGI("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    // 调用原始函数（使用处理后的参数）
    return original_sendData(curl_http, a2, a3, a4, a5, a6, a7, a8, 
                            final_a9, final_a10, final_a11, a12);
}

// Hook 后的 onHttpRequestCompleted 函数
static void* hooked_onHttpCompleted(
    void* curl_http,
    void* http_client,
    void* http_response) {
    
    LOGI("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGI("📥 [网络响应] CurlHttp::onHttpRequestCompleted");
    LOGI("  this: %p", curl_http);
    LOGI("  HttpClient: %p", http_client);
    LOGI("  HttpResponse: %p", http_response);
    
    // 存储响应字符串，供后续 parseJson 使用
    std::string response_text;
    
    // 尝试读取响应码（偏移 +0x28 处，HttpResponse::_responseCode）
    if (http_response) {
        int* response_code_ptr = (int*)((char*)http_response + 0x20);
        LOGI("  响应码: %d (可能)", *response_code_ptr);
        
        // 尝试读取响应数据长度（HttpResponse::_responseData vector）
        // vector 结构：{data*, size, capacity}
        struct ResponseDataVector {
            char* data;
            size_t size;
            size_t capacity;
        };
        
        ResponseDataVector* response_data = (ResponseDataVector*)((char*)http_response + 0x30);
        if (response_data && response_data->size > 0 && response_data->size < 100000) {
            LOGI("  响应数据大小: %zu 字节", response_data->size);
            
            // 保存完整响应文本
            if (response_data->data && response_data->size > 0) {
                response_text.assign(response_data->data, response_data->size);
                
                // 打印响应预览
                if (response_data->size <= 500) {
                    LOGI("  响应内容: %s", response_text.c_str());
                } else {
                    LOGI("  响应内容(前500): %.500s...", response_text.c_str());
                }
                
                // 解析响应格式：value1|value2|JSON
                // 使用 "|" 分隔符分割
                size_t first_bar = response_text.find('|');
                if (first_bar != std::string::npos) {
                    size_t second_bar = response_text.find('|', first_bar + 1);
                    if (second_bar != std::string::npos && second_bar + 1 < response_text.length()) {
                        // 提取 JSON 部分（第二个 | 之后）
                        std::string json_part = response_text.substr(second_bar + 1);
                        
                        // 保存到全局变量（简单方案）
                        g_last_json_string = json_part;
                        
                        LOGI("  💾 JSON部分(长度=%zu): %.300s%s", 
                             json_part.length(), 
                             json_part.c_str(),
                             json_part.length() > 300 ? "..." : "");
                    }
                }
            }
        }
    }
    
    LOGI("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    // 调用原始函数
    return original_onHttpCompleted(curl_http, http_client, http_response);
}

// Hook 后的 Json_create 函数
static void* hooked_json_create(const char* json_string) {
    // 调用原始函数创建 JSON 对象
    void* json_object = original_json_create(json_string);
    
    // 保存 JSON 对象指针和字符串的映射关系
    if (json_object && json_string) {
        size_t len = strnlen(json_string, 50000);  // 最多检查50KB
        if (len > 0 && len < 50000) {
            g_json_string_map[json_object] = std::string(json_string, len);
            LOGD("💾 [JSON创建] 对象=%p, 长度=%zu", json_object, len);
        }
    }
    
    return json_object;
}

// Hook 后的 Json_dispose 函数
static void hooked_json_dispose(void* json_object) {
    // 从映射表中删除
    auto it = g_json_string_map.find(json_object);
    if (it != g_json_string_map.end()) {
        LOGD("🗑️ [JSON释放] 对象=%p", json_object);
        g_json_string_map.erase(it);
    }
    
    // 调用原始函数
    original_json_dispose(json_object);
}

// Hook 后的 parseJson 函数
static void* hooked_parseJson(void* curl_http, int a2, void* json) {
    LOGI("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    LOGI("🔍 [JSON解析] CurlHttp::parseJson");
    LOGI("  this: %p", curl_http);
    LOGI("  操作类型ID: %d", a2);
    LOGI("  JSON对象: %p", json);
    
    // 从映射表中查找 JSON 字符串（使用 JSON 对象指针作为 key）
    auto it = g_json_string_map.find(json);
    if (it != g_json_string_map.end()) {
        const std::string& json_str = it->second;
        size_t len = json_str.length();
        
        LOGI("  📄 JSON长度: %zu 字节", len);
        
        if (len <= 800) {
            // 短 JSON，直接打印
            LOGI("  📄 JSON内容: %s", json_str.c_str());
        } else {
            // 长 JSON，打印前800字符和后200字符
            LOGI("  📄 JSON开头(800字符): %.800s...", json_str.c_str());
            if (len > 200) {
                const char* end_start = json_str.c_str() + (len - 200);
                LOGI("  📄 JSON结尾(200字符): ...%s", end_start);
            }
        }
    } else {
        LOGD("  ℹ️ 未找到 JSON 对象的字符串映射");
    }
    
    LOGI("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    // 调用原始函数
    return original_parseJson(curl_http, a2, json);
}

// ============================
// Cocos2d-x update 加速相关
// ============================

// Cocos2d-x update 函数的原始指针
typedef void (*UpdateFunc)(void* scheduler, float dt);
static UpdateFunc original_update = nullptr;

// Hook 后的 update 函数
static void hooked_update(void* scheduler, float dt) {
    // 修改 delta time，实现加速
    float modified_dt = dt * g_speed_multiplier;
    // LOGI("Cocos2d-x update: dt=%.4f -> %.4f (%.1fx速)", dt, modified_dt, g_speed_multiplier);
    original_update(scheduler, modified_dt);
}

// Hook 网络函数
void hookNetworkFunctions(GumModule* module) {
    LOGI("🌐 开始 Hook 网络函数...");
    GumInterceptor* interceptor = gum_interceptor_obtain();

    // Hook 1: CurlHttp::sendData (0x3b51dc)
    // 使用基址 + 偏移的方式
    const GumMemoryRange* range = gum_module_get_range(module);
    GumAddress base_addr = range->base_address;
    
    // 保存基址到全局变量（供 updateMoney/updateGold 使用）
    g_cocos2d_base_addr = base_addr;
    LOGI("📍 libcocos2dcpp.so 基址: 0x%lx", base_addr);
    
    GumAddress sendData_addr = base_addr + 0x3b51dc;
    LOGI("尝试 Hook sendData @ 0x%lx (base: 0x%lx + 0x3b51dc)", sendData_addr, base_addr);
    
    gum_interceptor_begin_transaction(interceptor);
    GumReplaceReturn ret1 = gum_interceptor_replace_fast(
        interceptor,
        GSIZE_TO_POINTER(sendData_addr),
        (gpointer)hooked_sendData,
        (gpointer*)&original_sendData
    );
    gum_interceptor_end_transaction(interceptor);
    
    if (ret1 == GUM_REPLACE_OK) {
        LOGI("✅ Hook sendData 成功");
    } else {
        LOGE("❌ Hook sendData 失败: 错误码 %d", ret1);
    }
    
    // Hook 2: CurlHttp::onHttpRequestCompleted (0x3bafa4)
    GumAddress onHttpCompleted_addr = base_addr + 0x3bafa4;
    LOGI("尝试 Hook onHttpRequestCompleted @ 0x%lx", onHttpCompleted_addr);
    
    gum_interceptor_begin_transaction(interceptor);
    GumReplaceReturn ret2 = gum_interceptor_replace_fast(
        interceptor,
        GSIZE_TO_POINTER(onHttpCompleted_addr),
        (gpointer)hooked_onHttpCompleted,
        (gpointer*)&original_onHttpCompleted
    );
    gum_interceptor_end_transaction(interceptor);
    
    if (ret2 == GUM_REPLACE_OK) {
        LOGI("✅ Hook onHttpRequestCompleted 成功");
    } else {
        LOGE("❌ Hook onHttpRequestCompleted 失败: 错误码 %d", ret2);
    }
    
    // Hook 3: CurlHttp::parseJson (0x3b6e74)
    GumAddress parseJson_addr = base_addr + 0x3b6e74;
    LOGI("尝试 Hook parseJson @ 0x%lx", parseJson_addr);
    
    gum_interceptor_begin_transaction(interceptor);
    GumReplaceReturn ret3 = gum_interceptor_replace_fast(
        interceptor,
        GSIZE_TO_POINTER(parseJson_addr),
        (gpointer)hooked_parseJson,
        (gpointer*)&original_parseJson
    );
    gum_interceptor_end_transaction(interceptor);
    
    if (ret3 == GUM_REPLACE_OK) {
        LOGI("✅ Hook parseJson 成功");
    } else {
        LOGE("❌ Hook parseJson 失败: 错误码 %d", ret3);
    }
    
    // Hook 4: Json_create (0x62ad8c)
    GumAddress json_create_addr = base_addr + 0x62ad8c;
    LOGI("尝试 Hook Json_create @ 0x%lx", json_create_addr);
    
    gum_interceptor_begin_transaction(interceptor);
    GumReplaceReturn ret4 = gum_interceptor_replace_fast(
        interceptor,
        GSIZE_TO_POINTER(json_create_addr),
        (gpointer)hooked_json_create,
        (gpointer*)&original_json_create
    );
    gum_interceptor_end_transaction(interceptor);
    
    if (ret4 == GUM_REPLACE_OK) {
        LOGI("✅ Hook Json_create 成功");
    } else {
        LOGE("❌ Hook Json_create 失败: 错误码 %d", ret4);
    }
    
    // Hook 5: Json_dispose (查找符号)
    // 先尝试通过符号查找
    GumAddress json_dispose_addr = 0;
    
    gum_module_enumerate_exports(module, 
        [](const GumExportDetails* details, gpointer user_data) {
            GumAddress* addr = (GumAddress*)user_data;
            std::string symbol_name(details->name);
            
            if (symbol_name.find("Json_dispose") != std::string::npos) {
                *addr = details->address;
                LOGI("✓ 找到 Json_dispose 符号: %s @ 0x%lx", details->name, details->address);
                return (gboolean)FALSE; // 停止枚举
            }
            
            return (gboolean)TRUE; // 继续枚举
        }, 
        &json_dispose_addr);
    
    if (json_dispose_addr != 0) {
        gum_interceptor_begin_transaction(interceptor);
        GumReplaceReturn ret5 = gum_interceptor_replace_fast(
            interceptor,
            GSIZE_TO_POINTER(json_dispose_addr),
            (gpointer)hooked_json_dispose,
            (gpointer*)&original_json_dispose
        );
        gum_interceptor_end_transaction(interceptor);
        
        if (ret5 == GUM_REPLACE_OK) {
            LOGI("✅ Hook Json_dispose 成功");
        } else {
            LOGE("❌ Hook Json_dispose 失败: 错误码 %d", ret5);
        }
    } else {
        LOGD("⚠️ 未找到 Json_dispose 符号（不影响核心功能）");
    }
    
    // Hook 6: Game_Unpack::updateMoney (0x3880c0)
    GumAddress updateMoney_addr = base_addr + 0x3880c0;
    LOGI("尝试 Hook updateMoney @ 0x%lx", updateMoney_addr);
    
    gum_interceptor_begin_transaction(interceptor);
    GumReplaceReturn ret6 = gum_interceptor_replace_fast(
        interceptor,
        GSIZE_TO_POINTER(updateMoney_addr),
        (gpointer)hooked_updateMoney,
        (gpointer*)&original_updateMoney
    );
    gum_interceptor_end_transaction(interceptor);
    
    if (ret6 == GUM_REPLACE_OK) {
        LOGI("✅ Hook updateMoney 成功");
    } else {
        LOGE("❌ Hook updateMoney 失败: 错误码 %d", ret6);
    }
    
    // Hook 7: Game_Unpack::updateGold (0x38813c)
    GumAddress updateGold_addr = base_addr + 0x38813c;
    LOGI("尝试 Hook updateGold @ 0x%lx", updateGold_addr);
    
    gum_interceptor_begin_transaction(interceptor);
    GumReplaceReturn ret7 = gum_interceptor_replace_fast(
        interceptor,
        GSIZE_TO_POINTER(updateGold_addr),
        (gpointer)hooked_updateGold,
        (gpointer*)&original_updateGold
    );
    gum_interceptor_end_transaction(interceptor);
    
    if (ret7 == GUM_REPLACE_OK) {
        LOGI("✅ Hook updateGold 成功");
    } else {
        LOGE("❌ Hook updateGold 失败: 错误码 %d", ret7);
    }
    
    LOGI("🌐 网络函数 Hook 完成");
}

// Hook Cocos2d-x update 函数
void hookCocos2dxUpdate(GumModule* module) {
    const std::string cache_key = "Scheduler_update";
    
    // 尝试从缓存读取符号名称
    std::string cached_symbol = readSymbolNameFromCache(cache_key);
    
    if (!cached_symbol.empty()) {
        LOGI("使用缓存的符号名进行 Hook: %s", cached_symbol.c_str());
        
        // 通过符号名直接查找地址
        GumAddress symbol_addr = gum_module_find_export_by_name(module, cached_symbol.c_str());
        
        if (symbol_addr != 0) {
            LOGI("✓ 找到符号地址: 0x%lx", symbol_addr);
            
            // 保存原始函数指针
            original_update = (UpdateFunc)symbol_addr;
            
            // 使用 Interceptor Hook
            GumInterceptor* interceptor = gum_interceptor_obtain();
            
            gum_interceptor_begin_transaction(interceptor);
            GumReplaceReturn ret = gum_interceptor_replace_fast(
                interceptor,
                GSIZE_TO_POINTER(symbol_addr),
                (gpointer)hooked_update,
                (gpointer*)&original_update
            );
            gum_interceptor_end_transaction(interceptor);
            
            if (ret == GUM_REPLACE_OK) {
                LOGI("🎯 Hook 成功 (缓存): %s (%.1fx 加速)", cached_symbol.c_str(), g_speed_multiplier);
                return;
            } else {
                LOGE("Hook 失败: 错误码 %d", ret);
            }
        } else {
            LOGE("缓存的符号名无效，重新搜索...");
        }
    }
    
    // 缓存未命中，重新搜索符号
    LOGI("搜索 Cocos2d-x Scheduler::update 符号...");
    
    // 正则表达式：Scheduler 类的 update 成员函数（大小写敏感）
    // 匹配格式：...Scheduler...update...
    std::regex pattern("Scheduler.*update");
    
    // 用于传递 cache_key 的结构
    struct HookContext {
        bool found;
        const char* cache_key;
    } ctx = {false, cache_key.c_str()};
    
    gum_module_enumerate_exports(module, 
        [](const GumExportDetails* details, gpointer user_data) {
            HookContext* ctx = (HookContext*)user_data;
            std::string symbol_name(details->name);
            
            // 使用正则匹配 Scheduler::update（大小写敏感）
            std::regex pattern("Scheduler.*update");
            
            if (std::regex_search(symbol_name, pattern)) {
                LOGI("✓ 匹配到符号: %s @ 0x%lx", details->name, details->address);
                
                // 保存原始函数指针
                original_update = (UpdateFunc)details->address;
                
                // 使用 Interceptor Hook
                GumInterceptor* interceptor = gum_interceptor_obtain();
                
                gum_interceptor_begin_transaction(interceptor);
                GumReplaceReturn ret = gum_interceptor_replace_fast(
                    interceptor,
                    GSIZE_TO_POINTER(details->address),
                    (gpointer)hooked_update,
                    (gpointer*)&original_update
                );
                gum_interceptor_end_transaction(interceptor);
                
                if (ret == GUM_REPLACE_OK) {
                    LOGI("🎯 Hook 成功: %s (%.1fx 加速)", details->name, g_speed_multiplier);
                    
                    // 保存符号名称到缓存
                    saveSymbolNameToCache(ctx->cache_key, details->name);
                    
                    ctx->found = true;
                    return (gboolean)FALSE; // 停止枚举
                } else {
                    LOGE("Hook 失败: %s (错误码: %d)", details->name, ret);
                }
            }
            
            return (gboolean)TRUE; // 继续枚举
        }, 
        &ctx);
    
    bool found = ctx.found;
    
    if (!found) {
        LOGE("未找到 Scheduler::update 符号");
    }
}

// Cocos2d-js evalString 相关
typedef bool (*EvalStringFunc)(void* script_engine, const char* code, int len, void* value, const char* path);
static EvalStringFunc original_evalString = nullptr;

// Hook 后的 evalString 函数
static bool hooked_evalString(void* script_engine, const char* code, int len, void* value, const char* path) {
 
    LOGD("length = %d ,%d", len, ++mycount);
  
    // 执行原始代码
    std::string js(code);
    return original_evalString(script_engine, js.c_str(), js.length(), value, path);
}

// Hook Cocos2d-js evalString 函数
void hookCocosEvalString(GumModule* module) {
    Timer timer("hookCocosEvalString");  // ⏱️ 计时开始
    const std::string cache_key = "ScriptEngine_evalString";
    
    // ✅ 读取缓存（带类型）
    CacheEntry cache = readFromCache(cache_key);
    timer.checkpoint("读取缓存");  // ⏱️ 检查点
    
    // 🎯 根据缓存类型分发
    if (cache.type == CacheType::SYMBOL) {
        // 方案1：使用符号名（dlsym 快速查找）
        LOGI("使用缓存的符号名进行 Hook: %s", cache.value.c_str());
        
        const char* module_path = gum_module_get_path(module);
        void* handle = dlopen(module_path, RTLD_NOLOAD);
        timer.checkpoint("dlopen");  // ⏱️ 检查点
        
        if (handle) {
            void* symbol_addr = dlsym(handle, cache.value.c_str());
            timer.checkpoint("dlsym");  // ⏱️ 检查点
            
            if (symbol_addr) {
                LOGI("✓ 找到符号地址: %p (通过 dlsym)", symbol_addr);
                
                original_evalString = (EvalStringFunc)symbol_addr;
                
                GumInterceptor* interceptor = gum_interceptor_obtain();
                gum_interceptor_begin_transaction(interceptor);
                GumReplaceReturn ret = gum_interceptor_replace_fast(
                    interceptor,
                    symbol_addr,
                    (gpointer)hooked_evalString,
                    (gpointer*)&original_evalString
                );
                gum_interceptor_end_transaction(interceptor);
                dlclose(handle);
                
                if (ret == GUM_REPLACE_OK) {
                    LOGI("🎯 Hook 成功 (符号缓存): %s", cache.value.c_str());
                    return;
                } else {
                    LOGE("Hook 失败: 错误码 %d", ret);
                }
            } else {
                LOGE("dlsym 未找到符号: %s", cache.value.c_str());
                dlclose(handle);
            }
        } else {
            LOGE("dlopen 失败: %s", dlerror());
        }
        
        LOGI("符号缓存失败，回退到搜索...");
        
    } else if (cache.type == CacheType::OFFSET) {
        // 方案2：使用偏移量（内存搜索结果）
        // 先获取 JNI 符号地址
        GumAddress jni_addr = gum_module_find_export_by_name(module, 
            "Java_com_cocos_lib_JsbBridge_nativeSendToScript");
        
        if (jni_addr == 0) {
            LOGE("未找到 JNI 符号，无法使用偏移缓存");
        } else {
            // 将十六进制字符串转换为偏移量
            char* endptr;
            gsize offset = strtoull(cache.value.c_str(), &endptr, 16);
            GumAddress target_addr = jni_addr + offset;
            
            LOGI("使用缓存的偏移量: 0x%lx (JNI: 0x%lx + 偏移: 0x%zx)", 
                 target_addr, jni_addr, offset);
            
            original_evalString = (EvalStringFunc)target_addr;
            
            GumInterceptor* interceptor = gum_interceptor_obtain();
            gum_interceptor_begin_transaction(interceptor);
            GumReplaceReturn ret = gum_interceptor_replace_fast(
                interceptor,
                GSIZE_TO_POINTER(target_addr),
                (gpointer)hooked_evalString,
                (gpointer*)&original_evalString
            );
            gum_interceptor_end_transaction(interceptor);
            
            if (ret == GUM_REPLACE_OK) {
                LOGI("🎯 Hook 成功 (偏移缓存): 0x%lx", target_addr);
                return;
            } else {
                LOGE("Hook 失败 (偏移缓存): 错误码 %d", ret);
            }
        }
    }
    
    // 缓存未命中，重新搜索符号
    LOGI("搜索 Cocos ScriptEngine::evalString 符号...");
    timer.checkpoint("开始符号枚举");  // ⏱️ 检查点
    
    // 正则表达式：ScriptEngine 类的 evalString 成员函数（大小写敏感）
    // 匹配格式：...ScriptEngine...evalString...
    std::regex pattern("ScriptEngine.*evalString");
    
    // 用于传递 cache_key 的结构
    struct HookContext {
        bool found;
        const char* cache_key;
        Timer* timer_ptr;
    } ctx = {false, cache_key.c_str(), &timer};
    
    gum_module_enumerate_exports(module, 
        [](const GumExportDetails* details, gpointer user_data) {
            HookContext* ctx = (HookContext*)user_data;
            std::string symbol_name(details->name);
            
            // 使用正则匹配 ScriptEngine::evalString（大小写敏感）
            std::regex pattern("ScriptEngine.*evalString");
            
            if (std::regex_search(symbol_name, pattern)) {
                LOGI("✓ 匹配到符号: %s @ 0x%lx", details->name, details->address);
                ctx->timer_ptr->checkpoint("找到符号");  // ⏱️ 检查点
                
                // 保存原始函数指针
                original_evalString = (EvalStringFunc)details->address;
                
                // 使用 Interceptor Hook
                GumInterceptor* interceptor = gum_interceptor_obtain();
                
                gum_interceptor_begin_transaction(interceptor);
                GumReplaceReturn ret = gum_interceptor_replace_fast(
                    interceptor,
                    GSIZE_TO_POINTER(details->address),
                    (gpointer)hooked_evalString,
                    (gpointer*)&original_evalString
                );
                gum_interceptor_end_transaction(interceptor);
                
                if (ret == GUM_REPLACE_OK) {
                    LOGI("🎯 Hook 成功: %s (JS 加速注入)", details->name);
                    
                    // 保存符号名称到缓存
                    saveSymbolNameToCache(ctx->cache_key, details->name);
                    
                    ctx->found = true;
                    return (gboolean)FALSE; // 停止枚举
                } else {
                    LOGE("Hook 失败: %s (错误码: %d)", details->name, ret);
                }
            }
            
            return (gboolean)TRUE; // 继续枚举
        }, 
        &ctx);
    
    bool found = ctx.found;
    
    if (!found) {
        LOGE("未找到 ScriptEngine::evalString 符号，尝试内存模式搜索...");
        
        // 🔍 后备方案：通过内存模式搜索
        // 步骤1：查找 JNI 桥接函数符号
        GumAddress jni_addr = gum_module_find_export_by_name(module, 
            "Java_com_cocos_lib_JsbBridge_nativeSendToScript");
        
        if (jni_addr == 0) {
            LOGE("也未找到 JNI 符号 Java_com_cocos_lib_JsbBridge_nativeSendToScript，放弃");
            return;
        }
        
        LOGI("✓ 找到 JNI 符号地址: 0x%lx", jni_addr);
        
        // 步骤2：计算搜索范围（从 JNI 符号到模块末尾）
        const GumMemoryRange* module_range = gum_module_get_range(module);
        GumAddress module_end = module_range->base_address + module_range->size;
        gsize search_size = module_end - jni_addr;
        
        LOGI("搜索范围: 0x%lx → 0x%lx (%.2f MB)", 
             jni_addr, module_end, search_size / 1024.0 / 1024.0);
        
        GumMemoryRange search_range = {
            .base_address = jni_addr,
            .size = search_size
        };
        
        // 步骤3：搜索内存模式
        // 模式：ret(C0 03 5F D6) + 固定字节(00) + 通配符(?? ??) + 固定字节(39) + ret(C0 03 5F D6)
        const char* pattern = "C0 03 5F D6 00 ?? ?? 39 C0 03 5F D6";
        GumMatchPattern* match_pattern = gum_match_pattern_new_from_string(pattern);
        
        if (!match_pattern) {
            LOGE("无效的内存模式");
            return;
        }
        
        Timer scan_timer("内存模式扫描");
        
        // 用于存储匹配结果
        struct ScanContext {
            std::vector<GumAddress> results;
            GumAddress base_addr;
        } scan_ctx;
        scan_ctx.base_addr = jni_addr;
        
        gum_memory_scan(&search_range, match_pattern, 
            [](GumAddress address, gsize size, gpointer user_data) {
                ScanContext* ctx = (ScanContext*)user_data;
                ctx->results.push_back(address);
                LOGI("✓ 匹配模式 @ 0x%lx (偏移: +0x%lx)", 
                     address, address - ctx->base_addr);
                return (gboolean)TRUE; // 继续搜索
            }, 
            &scan_ctx);
        
        gum_match_pattern_unref(match_pattern);
        
        LOGI("内存搜索完成，找到 %zu 个匹配", scan_ctx.results.size());
        
        // 步骤4：对找到的地址进行 Hook
        if (!scan_ctx.results.empty()) {
            // 使用第一个匹配的地址（通常是最接近 JNI 函数的）
            GumAddress target_addr = scan_ctx.results[0]+0xc;
            
            LOGI("使用匹配地址进行 Hook: 0x%lx", target_addr);
            
            // 保存原始函数指针
            original_evalString = (EvalStringFunc)target_addr;
            
            // 使用 Interceptor Hook
            GumInterceptor* interceptor = gum_interceptor_obtain();
            
            gum_interceptor_begin_transaction(interceptor);
            GumReplaceReturn ret = gum_interceptor_replace_fast(
                interceptor,
                GSIZE_TO_POINTER(target_addr),
                (gpointer)hooked_evalString,
                (gpointer*)&original_evalString
            );
            gum_interceptor_end_transaction(interceptor);
            
            if (ret == GUM_REPLACE_OK) {
                LOGI("🎯 Hook 成功 (通过内存搜索): 0x%lx", target_addr);
                
                // ✅ 保存偏移量到缓存（相对于 JNI 符号）
                gsize offset = target_addr - jni_addr;
                char offset_str[32];
                snprintf(offset_str, sizeof(offset_str), "0x%zx", offset);
                saveToCache(cache_key, CacheType::OFFSET, offset_str);
                LOGI("✓ 已缓存偏移量: +%s (相对于 JNI 符号)", offset_str);
            } else {
                LOGE("Hook 失败 (内存搜索): 错误码 %d", ret);
            }
        } else {
            LOGE("内存搜索未找到匹配的模式");
        }
    }
}

// Hook 函数分发
void dispatchHook(GameEngine engine, GumModule* module) {
    LOGI("引擎类型: %s", getEngineName(engine));
    
    switch (engine) {
        case GameEngine::UNITY:
            LOGI("准备 Hook Unity 加速函数...");
            // TODO: 实现 Unity hook 逻辑
            break;
            
        case GameEngine::UNREAL:
            LOGI("准备 Hook Unreal 加速函数...");
            // TODO: 实现 Unreal hook 逻辑
            break;
            
        case GameEngine::COCOS2D_CPP:
            LOGI("准备 Hook Cocos2d-x (C++) 加速函数...");
            hookCocos2dxUpdate(module);
            
            // 🌐 Hook 网络函数
            LOGI("准备 Hook 网络通信函数...");
            hookNetworkFunctions(module);
            break;
            
        case GameEngine::COCOS2D_JS:
            LOGI("准备 Hook Cocos2d-js (JavaScript) 加速函数...");
            hookCocosEvalString(module);
            break;
            
        case GameEngine::GODOT:
            LOGI("准备 Hook Godot 加速函数...");
            // TODO: 实现 Godot hook 逻辑
            break;
            
        default:
            LOGE("未知引擎类型，跳过 Hook");
            break;
    }
}

// 主工作线程
void workerThread() {
    Timer total_timer("工作线程总耗时");  // ⏱️ 总计时开始
    LOGI("工作线程启动");
    
    // 步骤 1：读取 maps 获取私有库
    LibraryMap library_map = parseMaps();
    total_timer.checkpoint("步骤1: parseMaps完成");  // ⏱️ 检查点
    
    // 步骤 2：查找 libcpp_shared.so 并提取包名
    std::string package_name;
    auto it = library_map.find("libcpp_shared.so");
    if (it != library_map.end()) {
        package_name = extractPackageName(it->second);
        g_pkg = package_name;  // 保存到全局变量，供 JS Hook 使用
        LOGI("从路径提取包名: %s (路径: %s)", package_name.c_str(), it->second.c_str());
    } else {
        LOGE("未找到 libcpp_shared.so，无法提取包名");
        return;
    }
    total_timer.checkpoint("步骤2: 提取包名完成");  // ⏱️ 检查点
    
    // 步骤 3：根据包名查找 base.apk 路径（带重试）
    std::string base_apk_path;
    int retry_count = 0;
    const int max_retries = 0xfffff; // 最多重试 30 次（30 秒）
    
    while (base_apk_path.empty() && retry_count < max_retries) {
        base_apk_path = findBaseApkPath(library_map, package_name);
        
        if (base_apk_path.empty()) {
            retry_count++;
            LOGI("未找到 base.apk 路径，1 秒后重试 (%d/%d)", retry_count, max_retries);
            usleep(1);
            library_map = parseMaps(); // 重新读取 maps
        }
    }
    
    if (base_apk_path.empty()) {
        LOGE("无法找到 base.apk 路径，放弃");
        return;
    }
    
    LOGI("找到 base.apk 路径: %s", base_apk_path.c_str());
    total_timer.checkpoint("步骤3: 找到base.apk完成");  // ⏱️ 检查点
    
    // 步骤 4：构造 lib 目录路径
    // 从 /data/app/~~xxx/pkg-xxx/base.apk 截断为 /data/app/~~xxx/pkg-xxx/
    size_t last_slash = base_apk_path.rfind('/');
    std::string app_dir = base_apk_path.substr(0, last_slash + 1);
    std::string lib_dir = app_dir + "lib/arm64/";
    
    LOGI("库目录路径: %s", lib_dir.c_str());
    
    // 步骤 5：执行 ls -l 命令，找到最大的库
    std::string target_lib = findLargestLibrary(lib_dir);
    total_timer.checkpoint("步骤5: findLargestLibrary完成");  // ⏱️ 检查点
    // target_lib="libluajapi.so";
    if (target_lib.empty()) {
        LOGE("未找到目标库");
        return;
    }
    
    LOGI("目标库: %s", target_lib.c_str());
    
    // 步骤 6：使用 Frida Gum 查找模块（带重试）
    GumModule* module = nullptr;
    retry_count = 0;
    
    while (!module  ) {
        module = gum_process_find_module_by_name(target_lib.c_str());
        
        if (!module) {
        //    retry_count++;
           LOGI("模块 %s 未加载，1 秒后重试 (%d/%d)",  target_lib.c_str(), retry_count, max_retries);
            usleep(1);
        }
    }
    
    if (!module) {
        LOGE("无法找到模块: %s", target_lib.c_str());
        return;
    }
    
    total_timer.checkpoint("步骤6: 找到模块完成");  // ⏱️ 检查点
    
    // 获取模块信息
    const gchar* module_name = gum_module_get_name(module);
    const gchar* module_path = gum_module_get_path(module);
    const GumMemoryRange* range = gum_module_get_range(module);
    
    LOGI("模块已加载:");
    LOGI("  名称: %s", module_name);
    LOGI("  路径: %s", module_path);
    LOGI("  基址: 0x%lx", range->base_address);
    LOGI("  大小: %zu 字节", range->size);
    
    // 步骤 7：识别游戏引擎
    GameEngine engine = identifyGameEngine(module);
    total_timer.checkpoint("步骤7: 识别引擎完成");  // ⏱️ 检查点
    
    // 步骤 8：分发 Hook
    dispatchHook(engine, module);
    total_timer.checkpoint("步骤8: Hook完成");  // ⏱️ 检查点
    
    g_object_unref(module);
    LOGI("工作流程完成");
}

// init_array 初始化函数
__attribute__((constructor))
static void init() {
    LOGI("初始化 Frida Gum");
    
    // 初始化 Frida Gum
    gum_init_embedded();
    
    // 创建工作线程（使用 C++ std::thread）
    std::thread worker(workerThread);
    worker.detach(); // 分离线程
    LOGI("工作线程已启动（分离模式）");
}

