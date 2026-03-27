module("luci.controller.vnt", package.seeall)
local luci_version = "v1.0.0"
local sys, http, nixio = require "luci.sys", require "luci.http", require "nixio"

local function json(d)
    http.prepare_content("application/json")
    http.write_json(d)
end

local function exec(c)
    return sys.exec(c .. " 2>/dev/null"):gsub("%s+$", "")
end

local function read(p)
    local f = io.open(p, "r")
    if not f then return end
    local c = f:read("*all")
    f:close()
    return c
end

local MIRRORS = {
    gitlab = "https://gitlab.com/api/v4/projects/whzhni%2F",
    github = "https://api.github.com/repos/vnt-dev/",
    gitee  = "https://gitee.com/api/v5/repos/whzhni/"
}

local function get_bin(typ)
    local uci = require "luci.model.uci".cursor()
    local sec = (typ == "server") and "vnts" or "vnt-cli"
    local opt = (typ == "server") and "vntsbin" or "clibin"
    local default = (typ == "server") and "/usr/bin/vnts" or "/usr/bin/vnt-cli"
    local bin = uci:get_first("vnt", sec, opt)
    if bin and bin ~= "" and nixio.fs.access(bin) then return bin end
    return default
end

local function runtime(f)
    local c = read(f)
    if not c then return "-" end
    local s = tonumber(c)
    if not s then return "-" end
    local d = os.time() - s
    local D, H, M = math.floor(d/86400), math.floor(d%86400/3600), math.floor(d%3600/60)
    return D > 0 and string.format("%d天%02d时%02d分", D, H, M) or string.format("%02d时%02d分%02d秒", H, M, d%60)
end

local function proc(n)
    if sys.call("pgrep " .. n .. " >/dev/null 2>&1") ~= 0 then return false, "-", "-" end
    local p = exec("pidof " .. n .. " | awk '{print $1}'")
    if p == "" then return true, "0%", "-" end
    local cpu = exec("top -b -n1 | awk '$1==" .. p .. "{print $7}'")
    local ram = exec("cat /proc/" .. p .. "/status | awk '/VmRSS/{printf \"%.1fMB\", $2/1024}'")
    return true, cpu ~= "" and cpu or "0%", ram ~= "" and ram or "-"
end

local function save_cfg(typ, singles, lists, extra)
    local uci = require "luci.model.uci".cursor()
    local sec = uci:get_first("vnt", typ)
    if not sec then return json({status = "error"}) end
    for _, n in ipairs(singles) do
        local v = http.formvalue(n)
        if v then uci:set("vnt", sec, n, v) end
    end
    for _, n in ipairs(lists or {}) do
        local items, i = {}, 1
        while http.formvalue(n.."."..i) do
            local v = http.formvalue(n.."."..i)
            if v ~= "" then items[#items+1] = v end
            i = i + 1
        end
        if #items > 0 then uci:set_list("vnt", sec, n, items) else uci:delete("vnt", sec, n) end
    end
    if extra then extra(uci, sec) end
    uci:commit("vnt")
    os.execute("/etc/init.d/vnt restart >/dev/null 2>&1 &")
    json({status = "ok"})
end

local function build_table(cmd, hdrs, row_fn, empty)
    local d = exec(cmd)
    if d == "" or d:match("[Ee]rror") or d:match("panicked") or d:match("Connection refused") then
        return json({html = "<div class='empty'>" .. (empty or "程序未运行") .. "</div>"})
    end
    local h = "<table class='dtable'><tr>"
    for _, hdr in ipairs(hdrs) do h = h .. "<th>" .. hdr .. "</th>" end
    h = h .. "</tr>"
    local first = true
    for l in d:gmatch("[^\r\n]+") do
        if first then first = false else
            local cols = {}
            for c in l:gmatch("%S+") do cols[#cols+1] = c end
            local row = row_fn(cols)
            if row then h = h .. row end
        end
    end
    json({html = h .. "</table>"})
end

local function log_op(op, t)
    local base = t == "s" and "/tmp/vnts" or "/tmp/vnt-cli"
    if op == "g" then
        http.write(read(base .. ".log") or "暂无日志")
    else
        os.execute("rm -f " .. base .. "*.log")
        json({status = "ok"})
    end
end

function index()
    if not nixio.fs.access("/etc/config/vnt") then return end
    entry({"admin", "vpn", "vnt"}, template("vnt/vnt_main"), _("VNT"), 44)
    local R = {"popup_client", "popup_server", "status", "restart", "get_log", "get_log2", "clear_log", "clear_log2", "get_config", "save_client", "save_server", "get_ifaces", "vnt_info", "vnt_list", "vnt_route", "vnt_chart", "vnt_cmd", "get_update", "do_install", "get_mirrors"}
    for _, r in ipairs(R) do
        entry({"admin", "vpn/vnt", r}, r:match("^popup_") and template("vnt/" .. r) or call(r)).leaf = true
    end
end

function status()
    local uci = require "luci.model.uci".cursor()
    local e = {}
    local cbin_path = uci:get_first("vnt", "vnt-cli", "clibin") or "/usr/bin/vnt-cli"
    local sbin_path = uci:get_first("vnt", "vnts", "vntsbin") or "/usr/bin/vnts"
    e.c_missing = nixio.fs.access(cbin_path) and 0 or 1
    e.s_missing = nixio.fs.access(sbin_path) and 0 or 1
    e.crunning, e.vntcpu, e.vntram = proc("vnt-cli")
    e.srunning, e.vntscpu, e.vntsram = proc("vnts")
    e.vntsta, e.vntsta2 = runtime("/tmp/vnt_time"), runtime("/tmp/vnts_time")
    e.web = tonumber(uci:get_first("vnt", "vnts", "web")) or 0
    e.port = tonumber(uci:get_first("vnt", "vnts", "web_port")) or 29870
    local token = uci:get_first("vnt", "vnt-cli", "token")
    e.token_set = (token and token ~= "") and 1 or 0
    local white = uci:get_first("vnt", "vnts", "white_Token")
    e.white_set = (white and ((type(white)=="table" and #white>0) or (type(white)=="string" and white~=""))) and 1 or 0
    e.mode = uci:get_first("vnt", "vnt-cli", "mode") or "dhcp"
    e.ipaddr = uci:get_first("vnt", "vnt-cli", "ipaddr") or ""
    e.vntshost = uci:get_first("vnt", "vnt-cli", "vntshost") or ""
    e.server_port = uci:get_first("vnt", "vnts", "server_port") or "29872"
    e.subnet = uci:get_first("vnt", "vnts", "subnet") or "10.26.0.1"
    e.netmask = uci:get_first("vnt", "vnts", "servern_netmask") or "255.255.255.0"
    local cbin = get_bin("client")
    local sbin = get_bin("server")
    e.vnttag = exec(cbin .. " -h 2>/dev/null | grep 'version:' | awk -F':' '{print $2}'")
    e.vntstag = exec(sbin .. " -V 2>/dev/null | awk '/^version:/{print $2}'")
    json(e)
end

function get_mirrors()
    json({ {"gitlab", "GitLab"}, {"github", "GitHub"}, {"gitee", "Gitee"} })
end

function get_config()
    local uci, e = require "luci.model.uci".cursor(), {}
    for _, c in ipairs({{"vnt-cli", "c_"}, {"vnts", "s_"}}) do
        local s = uci:get_first("vnt", c[1])
        if s then
            for k, v in pairs(uci:get_all("vnt", s)) do
                if k:sub(1,1) ~= "." then e[c[2]..k] = v end
            end
        end
    end
    e.s_public_key = read("/tmp/vnts_key/public_key.pem") or ""
    e.s_private_key = read("/tmp/vnts_key/private_key.pem") or ""
    json(e)
end

function get_ifaces()
    local r = {}
    for iface in exec("ls /sys/class/net"):gmatch("%S+") do
        local ip = exec("ip -4 addr show " .. iface .. " | awk '/inet /{print $2}' | cut -d'/' -f1")
        if ip ~= "" then r[#r+1] = {name = iface, ip = ip} end
    end
    json(r)
end

function save_client()
    save_cfg("vnt-cli", {"enabled", "token", "mode", "ipaddr", "desvice_id", "desvice_name", "forward", "allow_wg", "log", "clibin", "vntshost", "tunname", "relay", "punch", "passmode", "key", "client_port", "mtu", "local_dev", "serverw", "finger", "first_latency", "disable_stats", "check", "checktime", "comp"}, {"localadd", "peeradd", "vntdns", "stunhost", "mapping", "checkip", "vnt_forward"})
end

function save_server()
    save_cfg("vnts", {"enabled", "server_port", "subnet", "servern_netmask", "web", "web_port", "webuser", "webpass", "web_wan", "logs", "vntsbin", "sfinger"}, {"white_Token"}, function(uci, sec)
        for _, k in ipairs({"public_key", "private_key"}) do
            local v = http.formvalue(k)
            if v and v ~= "" then
                nixio.fs.mkdir("/tmp/vnts_key")
                nixio.fs.writefile("/tmp/vnts_key/" .. k .. ".pem", v:gsub("\r\n", "\n"))
            end
        end
    end)
end

function restart()
    sys.call("/etc/init.d/vnt restart >/dev/null 2>&1 &")
    json({status = "ok"})
end

function get_log() log_op("g", "c") end
function get_log2() log_op("g", "s") end
function clear_log() log_op("c", "c") end
function clear_log2() log_op("c", "s") end

function vnt_info()
    local running = proc("vnt-cli")
    if not running then return json({html = "<pre>程序未运行</pre>"}) end
    local cbin = get_bin("client")
    local info = exec(cbin .. " --info 2>/dev/null")
    if info == "" then info = "程序运行中但无法获取详细信息" end
    for en, cn in pairs({["Name"]="设备名称", ["Connection status"]="连接状态", ["Virtual ip"]="虚拟IP", ["Virtual gateway"]="虚拟网关", ["Virtual netmask"]="虚拟掩码", ["NAT type"]="NAT类型", ["Relay server"]="服务器", ["Public ips"]="外网IP", ["Local addr"]="本地地址"}) do
        info = info:gsub(en, cn)
    end
    json({html = "<pre>" .. info .. "</pre>"})
end

function vnt_list()
    if not proc("vnt-cli") then return json({html = "<div class='empty'>程序未运行</div>"}) end
    local cbin = get_bin("client")
    build_table(cbin .. " --all 2>/dev/null", {"名称", "虚拟IP", "状态", "模式", "延迟", "NAT", "公网IP"},
        function(c)
            if #c < 3 then return nil end
            if c[3]:lower() == "online" and #c >= 7 then
                local rt = tonumber(c[5]) or 0
                return string.format("<tr><td><b>%s</b></td><td><code>%s</code></td><td class='on'>● 在线</td><td>%s</td><td class='%s'>%sms</td><td>%s</td><td>%s</td></tr>",
                    c[1], c[2], c[4]:upper(), rt < 50 and "on" or (rt < 100 and "warn" or "off"), c[5], c[6], c[7])
            end
            return string.format("<tr><td><b>%s</b></td><td><code>%s</code></td><td class='off'>● 离线</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>", c[1], c[2])
        end, "暂无设备")
end

function vnt_route()
    if not proc("vnt-cli") then return json({html = "<div class='empty'>程序未运行</div>"}) end
    local cbin = get_bin("client")
    build_table(cbin .. " --route 2>/dev/null", {"目标", "下一跳", "跃点", "延迟", "接口"},
        function(c) return #c >= 5 and string.format("<tr><td>%s</td><td>%s</td><td>%s</td><td>%sms</td><td>%s</td></tr>", c[1], c[2], c[3], c[4], c[5]) or nil end)
end

function vnt_chart()
    if not proc("vnt-cli") then return json({html = "<div class='empty'>程序未运行</div>"}) end
    local cbin = get_bin("client")
    local raw = sys.exec(cbin .. " --chart_a 2>&1") or ""
    if raw == "" or raw:match("Error") or raw:match("error") or raw:match("panicked") then return json({html = "<div class='empty'>获取流量失败</div>"}) end
    if raw:match("not enabled") then return json({html = "<div class='empty'>📊 流量统计未启用<br><small style='color:var(--text2)'>请在客户端设置中启用</small></div>"}) end
    local up = raw:match("Upload total%s*=%s*([^\r\n]+)") or "-"
    local dn = raw:match("Download total%s*=%s*([^\r\n]+)") or "-"
    local html = "<div class='info-row' style='justify-content:center;gap:40px;font-weight:bold;border:none'><span class='on'>↑ " .. up:gsub("%s+$","") .. "</span><span style='color:var(--accent)'>↓ " .. dn:gsub("%s+$","") .. "</span></div>"
    html = html .. "<table class='dtable'><tr><th>IP地址</th><th>方向</th><th>流量图</th><th>流量</th></tr>"
    for line in raw:gmatch("[^\r\n]+") do
        local ip = line:match("(%d+%.%d+%.%d+%.%d+)%s*|")
        if ip then
            local bars = line:match("(█+)") or ""
            local dir, size, cls = "↑", "-", "on"
            if line:match("download") then dir, cls = "↓", "link"; size = line:match("download%s+(.+)") or "-"
            elseif line:match("upload") then size = line:match("upload%s+(.+)") or "-" end
            html = html .. string.format("<tr><td><code>%s</code></td><td class='%s'>%s</td><td class='warn'>%s</td><td>%s</td></tr>", ip, cls, dir, bars, size:gsub("%s+$",""))
        end
    end
    json({html = html .. "</table>"})
end

function vnt_cmd()
    local function get_cmdline(pname)
        local pid = exec("pidof " .. pname)
        if pid and pid ~= "" then pid = pid:match("^%d+") if pid then return exec("cat /proc/" .. pid .. "/cmdline | tr '\\0' ' '") end end
        return "未运行"
    end
    local c1 = get_cmdline("vnt-cli")
    local c2 = get_cmdline("vnts")
    json({html = "<pre><b>vnt-cli:</b>\n" .. (c1 ~= "" and c1 or "未运行") .. "\n\n<b>vnts:</b>\n" .. (c2 ~= "" and c2 or "未运行") .. "</pre>"})
end

local function pkg_info()
    if sys.call("command -v opkg >/dev/null 2>&1") == 0 then return "opkg", "ipk", exec("opkg print-architecture | awk '!/all|noarch/{a=$2}END{print a}'") end
    if sys.call("command -v apk >/dev/null 2>&1") == 0 then return "apk", "apk", exec("apk --print-arch") end
    return "unknown", "ipk", ""
end

local function ensure_dep(pkg)
    if sys.call("command -v " .. pkg .. " >/dev/null 2>&1") == 0 then return true end
    local mgr
    if sys.call("command -v opkg >/dev/null 2>&1") == 0 then mgr = "opkg install"
    elseif sys.call("command -v apk >/dev/null 2>&1") == 0 then mgr = "apk add --allow-untrusted" end
    if mgr then sys.call(mgr .. " " .. pkg .. " >/dev/null 2>&1") end
    return sys.call("command -v " .. pkg .. " >/dev/null 2>&1") == 0
end

local function fetch_api(api_url)
    local cmd
    if sys.call("command -v wget >/dev/null 2>&1") == 0 then
        cmd = "wget -qO- --timeout=10 '" .. api_url .. "' 2>/dev/null"
    else
        cmd = "curl -sL --connect-timeout 10 '" .. api_url .. "' 2>/dev/null"
    end
    return exec(cmd .. " | sed 's/\": /\":/g'")
end

function get_update()
    local mgr, ext, arch = pkg_info()
    local t = http.formvalue("type") or "client"
    local mirror = http.formvalue("mirror") or "gitlab"
    local api_name = "vnt"
    if t == "server" then api_name = "vnts" end
    local base = MIRRORS[mirror] or MIRRORS["gitlab"]
    local url_path
    if mirror == "github" then
        url_path = base .. api_name .. "/releases/latest"
    else
        url_path = base .. api_name .. "/releases"
    end
    local data = fetch_api(url_path)
    if not data or data == "" then return json({version = "-", mgr = mgr, arch = arch, files = {}, api_name = api_name, mirror = mirror}) end
    local files = {}
    for f in data:gmatch('"([^"]+[%w%-%.]+)"') do
        if not f:match("/") and not f:match("src%-") and not f:match("debug") then
            if f:match("^" .. api_name .. ".*%.tar%.gz$") or f:match("%.?" .. ext .. "$") then
                files[#files+1] = f
            end
        end
    end
    json({
        version = data:match('"tag_name":"v?([^"]+)"') or "-",
        mgr = mgr, arch = arch, files = files, api_name = api_name, mirror = mirror, luci_version = luci_version 
    })
end

function do_install()
    local file = http.formvalue("file")
    local api = http.formvalue("api") or "vnt"
    local mirror = http.formvalue("mirror") or "gitlab"
    if not file or file == "" then
        return json({status = "error", msg = "未指定文件"})
    end
    if not ensure_dep("wget") then ensure_dep("curl") end
    if not ensure_dep("tar") then return json({status = "error", msg = "无法安装解压工具 tar"}) end
    local base = MIRRORS[mirror] or MIRRORS["gitlab"]
    local api_url = (mirror == "github") and (base .. api .. "/releases/latest") or (base .. api .. "/releases")
    local data = fetch_api(api_url)
    if not data then return json({status = "error", msg = "获取版本信息失败"}) end
    local url = data:match('"browser_download_url":"([^"]+)"')
    if not url then
        url = data:match('(https?://[^"]+/' .. file:gsub("([%.%-%+])", "%%%1") .. ')')
    end
    if not url then return json({status = "error", msg = "未找到下载链接"}) end
    local tmp_file = "/tmp/" .. file
    local dl_cmd = sys.call("command -v wget >/dev/null 2>&1") == 0 
        and "wget -q --timeout=120 '" .. url .. "' -O '" .. tmp_file .. "'" 
        or "curl -sL --connect-timeout 120 -o '" .. tmp_file .. "' '" .. url .. "'"
    if sys.call(dl_cmd) ~= 0 then
        sys.call("rm -f " .. tmp_file)
        return json({status = "error", msg = "下载失败"})
    end
    local uci = require "luci.model.uci".cursor()
    local result_msg = ""
    local need_restart = false
    if file:match("%.tar%.gz$") then
        local clibin = uci:get_first("vnt", "vnt-cli", "clibin") or "/usr/bin/vnt-cli"
        local vntsbin = uci:get_first("vnt", "vnts", "vntsbin") or "/usr/bin/vnts"
        local tmp_dir = "/tmp/vnt_extract_" .. os.time()
        sys.call("mkdir -p " .. tmp_dir)
        if sys.call("tar -xzf " .. tmp_file .. " -C " .. tmp_dir) ~= 0 then
            sys.call("rm -rf " .. tmp_dir .. " " .. tmp_file)
            return json({status = "error", msg = "解压失败"})
        end
        local f_cli = exec("find " .. tmp_dir .. " -name 'vnt-cli' -type f | head -n 1")
        if f_cli ~= "" then
            sys.call("mv -f '" .. f_cli .. "' '" .. clibin .. "' && chmod +x '" .. clibin .. "'")
            result_msg = result_msg .. "vnt-cli -> " .. clibin .. "\n"
            need_restart = true
        end
        local f_vnts = exec("find " .. tmp_dir .. " -name 'vnts' -type f | head -n 1")
        if f_vnts ~= "" then
            sys.call("mv -f '" .. f_vnts .. "' '" .. vntsbin .. "' && chmod +x '" .. vntsbin .. "'")
            result_msg = result_msg .. "vnts -> " .. vntsbin .. "\n"
            need_restart = true
        end
        sys.call("sync")
        sys.call("rm -rf " .. tmp_dir .. " " .. tmp_file)

        if result_msg == "" then
            result_msg = "未找到二进制文件"
            need_restart = false
        end
    else
        local mgr_cmd = (sys.call("command -v opkg >/dev/null 2>&1") == 0) and "opkg install" or "apk add --allow-untrusted"
        result_msg = sys.exec(mgr_cmd .. " '" .. tmp_file .. "' 2>&1")
        sys.call("rm -f " .. tmp_file)
        need_restart = true
    end

    if need_restart then
        sys.call("/etc/init.d/vnt restart >/dev/null 2>&1 &")
        result_msg = result_msg .. "\n服务已重启"
    end

    json({status = "ok", msg = result_msg})
end
