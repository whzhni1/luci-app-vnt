local m, s

m = Map("vnt", translate("vnt-cli 设置"))
m.redirect = luci.dispatcher.build_url("admin/vpn/vnt")

s = m:section(TypedSection, "vnt-cli")
s.anonymous = true
s:tab("general", translate("基本设置"))
s:tab("privacy", translate("高级设置"))
s:tab("upload", translate("上传程序"))

-- ===== 基本设置 =====
s:taboption("general", Flag, "enabled", translate("启用")).rmempty = false

local token = s:taboption("general", Value, "token", translate("Token"))
token.password = true
token.placeholder = "必填，虚拟局域网标识"

local mode = s:taboption("general", ListValue, "mode", translate("接口模式"))
mode:value("dhcp", translate("动态分配"))
mode:value("static", translate("手动指定"))

local ipaddr = s:taboption("general", Value, "ipaddr", translate("接口IP"))
ipaddr:depends("mode", "static")
ipaddr.datatype = "ip4addr"

local desvice_id = s:taboption("general", Value, "desvice_id", translate("设备ID"))
local localadd = s:taboption("general", DynamicList, "localadd", translate("本地网段"))
localadd.placeholder = "192.168.1.0/24"

local peeradd = s:taboption("general", DynamicList, "peeradd", translate("对端网段"))
peeradd.placeholder = "192.168.2.0/24,10.26.0.3"

s:taboption("general", Flag, "forward", translate("启用IP转发")).rmempty = false
s:taboption("general", Flag, "allow_wg", translate("允许WireGuard")).rmempty = false
s:taboption("general", Flag, "log", translate("启用日志")).rmempty = false

-- ===== 高级设置 =====
local clibin = s:taboption("privacy", Value, "clibin", translate("程序路径"))
clibin.placeholder = "/usr/bin/vnt-cli"

local vntshost = s:taboption("privacy", Value, "vntshost", translate("服务器地址"))
vntshost.placeholder = "tcp://域名:端口"

local desvice_name = s:taboption("privacy", Value, "desvice_name", translate("设备名称"))
local tunname = s:taboption("privacy", Value, "tunname", translate("网卡名称"))
tunname.placeholder = "vnt-tun"

local relay = s:taboption("privacy", ListValue, "relay", translate("传输模式"))
relay:value("自动")
relay:value("转发")
relay:value("P2P")

local punch = s:taboption("privacy", ListValue, "punch", translate("打洞模式"))
punch:value("all", "都使用")
punch:value("ipv4", "仅IPv4")
punch:value("ipv6", "仅IPv6")

local passmode = s:taboption("privacy", ListValue, "passmode", translate("加密模式"))
passmode:value("off", "不加密")
passmode:value("aes_gcm", "AES-GCM")
passmode:value("aes_cbc", "AES-CBC")
passmode:value("aes_ecb", "AES-ECB")
passmode:value("chacha20_poly1305", "ChaCha20-Poly1305")

local key = s:taboption("privacy", Value, "key", translate("加密密钥"))
key.password = true
key:depends({passmode="aes_gcm"})
key:depends({passmode="aes_cbc"})
key:depends({passmode="aes_ecb"})
key:depends({passmode="chacha20_poly1305"})

s:taboption("privacy", Flag, "serverw", translate("服务端加密")).rmempty = false
s:taboption("privacy", Flag, "finger", translate("指纹校验")).rmempty = false
s:taboption("privacy", Flag, "first_latency", translate("优化传输")).rmempty = false

-- ===== 上传程序 =====
local upload = s:taboption("upload", FileUpload, "upload_file")
upload.template = "vnt/other_upload"

return m
