module("luci.controller.vnt", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/vnt") then return end
	
	-- 主页面
	entry({"admin", "vpn", "vnt"}, template("vnt/vnt_main"), _("VNT"), 44)
	-- 设置弹窗
	entry({"admin", "vpn", "vnt", "client"}, cbi("vnt_client"), nil).leaf = true
	entry({"admin", "vpn", "vnt", "server"}, cbi("vnt_server"), nil).leaf = true
	-- API
	entry({"admin", "vpn", "vnt", "status"}, call("act_status")).leaf = true
	entry({"admin", "vpn", "vnt", "get_log"}, call("get_log")).leaf = true
	entry({"admin", "vpn", "vnt", "get_log2"}, call("get_log2")).leaf = true
	entry({"admin", "vpn", "vnt", "clear_log"}, call("clear_log")).leaf = true
	entry({"admin", "vpn", "vnt", "clear_log2"}, call("clear_log2")).leaf = true
	entry({"admin", "vpn", "vnt", "vnt_info"}, call("vnt_info")).leaf = true
	entry({"admin", "vpn", "vnt", "vnt_list"}, call("vnt_list")).leaf = true
	entry({"admin", "vpn", "vnt", "vnt_route"}, call("vnt_route")).leaf = true
	entry({"admin", "vpn", "vnt", "vnt_cmd"}, call("vnt_cmd")).leaf = true
end

-- 状态API
function act_status()
	local sys = require "luci.sys"
	local uci = require "luci.model.uci".cursor()
	local e = {}
	
	-- 基本状态
	e.crunning = sys.call("pgrep vnt-cli >/dev/null") == 0
	e.srunning = sys.call("pgrep vnts >/dev/null") == 0
	e.web = tonumber(uci:get_first("vnt", "vnts", "web")) or 0
	e.port = tonumber(uci:get_first("vnt", "vnts", "web_port")) or 29870
	
	-- Token状态
	local token = uci:get_first("vnt", "vnt-cli", "token")
	e.token_set = (token and token ~= "") and 1 or 0
	local white = uci:get_first("vnt", "vnts", "white_Token")
	e.white_set = (white and #white > 0) and 1 or 0
	
	-- 客户端设置摘要
	e.mode = uci:get_first("vnt", "vnt-cli", "mode") or "dhcp"
	e.ipaddr = uci:get_first("vnt", "vnt-cli", "ipaddr") or ""
	e.vntshost = uci:get_first("vnt", "vnt-cli", "vntshost") or ""
	
	-- 服务端设置摘要
	e.server_port = uci:get_first("vnt", "vnts", "server_port") or "29872"
	e.subnet = uci:get_first("vnt", "vnts", "subnet") or "10.26.0.1"
	e.netmask = uci:get_first("vnt", "vnts", "servern_netmask") or "255.255.255.0"
	
	-- 运行时间和资源
	local function get_runtime(file)
		local f = io.open(file, "r")
		if f then
			local t = f:read("*all"); f:close()
			if t and t ~= "" then
				local start = tonumber(t)
				if start then
					local diff = os.time() - start
					local d = math.floor(diff / 86400)
					local h = math.floor((diff % 86400) / 3600)
					local m = math.floor((diff % 3600) / 60)
					local s = diff % 60
					if d > 0 then return string.format("%d天%02d时%02d分%02d秒", d, h, m, s)
					else return string.format("%02d时%02d分%02d秒", h, m, s) end
				end
			end
		end
		return "-"
	end
	e.vntsta = get_runtime("/tmp/vnt_time")
	e.vntsta2 = get_runtime("/tmp/vnts_time")
	
	-- CPU和内存
	local function get_res(proc)
		local cpu = sys.exec("top -b -n1 2>/dev/null | grep " .. proc .. " | grep -v grep | awk '{print $(NF-1)}'"):gsub("%s+", "")
		local mem = sys.exec("cat /proc/$(pidof " .. proc .. " 2>/dev/null | awk '{print $NF}')/status 2>/dev/null | grep VmRSS | awk '{printf \"%.2f MB\", $2/1024}'")
		return cpu ~= "" and cpu or "0%", mem ~= "" and mem or "-"
	end
	e.vntcpu, e.vntram = get_res("vnt-cli")
	e.vntscpu, e.vntsram = get_res("vnts")
	
	-- 版本
	local function get_ver(cmd) return sys.exec(cmd):gsub("%s+", "") end
	e.vnttag = get_ver("$(uci -q get vnt.@vnt-cli[0].clibin) -h 2>/dev/null | grep 'version:' | awk -F':' '{print $2}'")
	e.vntstag = get_ver("$(uci -q get vnt.@vnts[0].vntsbin) -V 2>/dev/null | awk -F': ' '{print $2}'")
	
	luci.http.prepare_content("application/json")
	luci.http.write_json(e)
end

-- 日志API
function get_log()
	local f = io.open("/tmp/vnt-cli.log", "r")
	luci.http.write(f and f:read("*all") or "暂无日志"); if f then f:close() end
end

function get_log2()
	local f = io.open("/tmp/vnts.log", "r")
	luci.http.write(f and f:read("*all") or "暂无日志"); if f then f:close() end
end

function clear_log() luci.sys.call("rm -f /tmp/vnt-cli*.log") end
function clear_log2() luci.sys.call("rm -f /tmp/vnts*.log") end

-- 信息API
function vnt_info()
	local info = luci.sys.exec("$(uci -q get vnt.@vnt-cli[0].clibin) --info 2>&1")
	if info == "" then info = "错误：程序未运行" end
	luci.http.prepare_content("application/json")
	luci.http.write_json({ html = "<pre>" .. info .. "</pre>" })
end

function vnt_list()
	local list = luci.sys.exec("$(uci -q get vnt.@vnt-cli[0].clibin) --list 2>&1")
	if list == "" then
		luci.http.prepare_content("application/json")
		luci.http.write_json({ html = "<div class='empty'>程序未运行或暂无设备</div>" })
		return
	end
	local html = "<table class='dtable'><thead><tr><th>名称</th><th>虚拟IP</th><th>状态</th><th>模式</th><th>延迟</th></tr></thead><tbody>"
	local first = true
	for line in list:gmatch("[^\r\n]+") do
		if first then first = false
		else
			local cols = {}
			for col in line:gmatch("%S+") do table.insert(cols, col) end
			if #cols >= 5 then
				local status_cls = cols[3]:lower() == "online" and "on" or "off"
				local mode_cls = cols[4]:lower() == "p2p" and "p2p" or "relay"
				local rt = tonumber(cols[5]) or 0
				local rt_cls = rt < 50 and "good" or (rt < 100 and "mid" or "bad")
				html = html .. string.format(
					"<tr><td><b>%s</b></td><td><code>%s</code></td><td class='st-%s'>●%s</td><td class='md-%s'>%s</td><td class='rt-%s'>%sms</td></tr>",
					cols[1], cols[2], status_cls, cols[3], mode_cls, cols[4]:upper(), rt_cls, cols[5])
			end
		end
	end
	html = html .. "</tbody></table>"
	luci.http.prepare_content("application/json")
	luci.http.write_json({ html = html })
end

function vnt_route()
	local route = luci.sys.exec("$(uci -q get vnt.@vnt-cli[0].clibin) --route 2>&1")
	if route == "" then route = "程序未运行" end
	luci.http.prepare_content("application/json")
	luci.http.write_json({ html = "<pre>" .. route .. "</pre>" })
end

function vnt_cmd()
	local cmd = luci.sys.exec("cat /proc/$(pidof vnt-cli 2>/dev/null)/cmdline 2>/dev/null | tr '\\0' ' '")
	if cmd == "" then cmd = "程序未运行" end
	luci.http.prepare_content("application/json")
	luci.http.write_json({ html = "<pre>" .. cmd .. "</pre>" })
end
