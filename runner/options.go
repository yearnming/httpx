package runner

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/exp/maps"

	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/goconfig"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/httpx/common/customextract"
	"github.com/projectdiscovery/httpx/common/customheader"
	"github.com/projectdiscovery/httpx/common/customlist"
	customport "github.com/projectdiscovery/httpx/common/customports"
	fileutilz "github.com/projectdiscovery/httpx/common/fileutil"
	"github.com/projectdiscovery/httpx/common/slice"
	"github.com/projectdiscovery/httpx/common/stringz"
	"github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/env"
	fileutil "github.com/projectdiscovery/utils/file"
	updateutils "github.com/projectdiscovery/utils/update"
)

const (
	two                    = 2
	DefaultResumeFile      = "resume.cfg"
	DefaultOutputDirectory = "output"
)

var PDCPApiKey = ""

// OnResultCallback (hostResult)
type OnResultCallback func(Result)

type ScanOptions struct {
	Methods                   []string
	StoreResponseDirectory    string
	RequestURI                string
	RequestBody               string
	VHost                     bool
	OutputTitle               bool
	OutputStatusCode          bool
	OutputLocation            bool
	OutputContentLength       bool
	StoreResponse             bool
	OutputServerHeader        bool
	OutputWebSocket           bool
	OutputWithNoColor         bool
	OutputMethod              bool
	ResponseHeadersInStdout   bool
	ResponseInStdout          bool
	Base64ResponseInStdout    bool
	ChainInStdout             bool
	TLSProbe                  bool
	CSPProbe                  bool
	VHostInput                bool
	OutputContentType         bool
	Unsafe                    bool
	Pipeline                  bool
	HTTP2Probe                bool
	OutputIP                  bool
	OutputCName               bool
	OutputCDN                 string
	OutputResponseTime        bool
	PreferHTTPS               bool
	NoFallback                bool
	NoFallbackScheme          bool
	TechDetect                string
	StoreChain                bool
	StoreVisionReconClusters  bool
	MaxResponseBodySizeToSave int
	MaxResponseBodySizeToRead int
	OutputExtractRegex        string
	extractRegexps            map[string]*regexp.Regexp
	ExcludeCDN                bool
	HostMaxErrors             int
	ProbeAllIPS               bool
	Favicon                   bool
	LeaveDefaultPorts         bool
	OutputLinesCount          bool
	OutputWordsCount          bool
	Hashes                    string
	Screenshot                bool
	UseInstalledChrome        bool
	DisableStdin              bool
	NoScreenshotBytes         bool
	NoHeadlessBody            bool
	ScreenshotTimeout         int
}

func (s *ScanOptions) Clone() *ScanOptions {
	return &ScanOptions{
		Methods:                   s.Methods,
		StoreResponseDirectory:    s.StoreResponseDirectory,
		RequestURI:                s.RequestURI,
		RequestBody:               s.RequestBody,
		VHost:                     s.VHost,
		OutputTitle:               s.OutputTitle,
		OutputStatusCode:          s.OutputStatusCode,
		OutputLocation:            s.OutputLocation,
		OutputContentLength:       s.OutputContentLength,
		StoreResponse:             s.StoreResponse,
		OutputServerHeader:        s.OutputServerHeader,
		OutputWebSocket:           s.OutputWebSocket,
		OutputWithNoColor:         s.OutputWithNoColor,
		OutputMethod:              s.OutputMethod,
		ResponseHeadersInStdout:   s.ResponseHeadersInStdout,
		ResponseInStdout:          s.ResponseInStdout,
		Base64ResponseInStdout:    s.Base64ResponseInStdout,
		ChainInStdout:             s.ChainInStdout,
		TLSProbe:                  s.TLSProbe,
		CSPProbe:                  s.CSPProbe,
		OutputContentType:         s.OutputContentType,
		Unsafe:                    s.Unsafe,
		Pipeline:                  s.Pipeline,
		HTTP2Probe:                s.HTTP2Probe,
		OutputIP:                  s.OutputIP,
		OutputCName:               s.OutputCName,
		OutputCDN:                 s.OutputCDN,
		OutputResponseTime:        s.OutputResponseTime,
		PreferHTTPS:               s.PreferHTTPS,
		NoFallback:                s.NoFallback,
		NoFallbackScheme:          s.NoFallbackScheme,
		TechDetect:                s.TechDetect,
		StoreChain:                s.StoreChain,
		OutputExtractRegex:        s.OutputExtractRegex,
		MaxResponseBodySizeToSave: s.MaxResponseBodySizeToSave,
		MaxResponseBodySizeToRead: s.MaxResponseBodySizeToRead,
		HostMaxErrors:             s.HostMaxErrors,
		Favicon:                   s.Favicon,
		extractRegexps:            s.extractRegexps,
		LeaveDefaultPorts:         s.LeaveDefaultPorts,
		OutputLinesCount:          s.OutputLinesCount,
		OutputWordsCount:          s.OutputWordsCount,
		Hashes:                    s.Hashes,
		Screenshot:                s.Screenshot,
		UseInstalledChrome:        s.UseInstalledChrome,
		NoScreenshotBytes:         s.NoScreenshotBytes,
		NoHeadlessBody:            s.NoHeadlessBody,
		ScreenshotTimeout:         s.ScreenshotTimeout,
	}
}

// Options contains configuration options for httpx.
type Options struct {
	CustomHeaders             customheader.CustomHeaders
	CustomPorts               customport.CustomPorts
	matchStatusCode           []int
	matchContentLength        []int
	filterStatusCode          []int
	filterContentLength       []int
	Output                    string
	OutputAll                 bool
	StoreResponseDir          string
	HTTPProxy                 string
	SocksProxy                string
	InputFile                 string
	InputTargetHost           goflags.StringSlice
	Methods                   string
	RequestURI                string
	RequestURIs               string
	requestURIs               []string
	OutputMatchStatusCode     string
	OutputMatchContentLength  string
	OutputFilterStatusCode    string
	OutputFilterErrorPage     bool
	OutputFilterContentLength string
	InputRawRequest           string
	rawRequest                string
	RequestBody               string
	OutputFilterString        string
	OutputMatchString         string
	OutputFilterRegex         string
	OutputMatchRegex          string
	Retries                   int
	Threads                   int
	Timeout                   int
	Delay                     time.Duration
	filterRegex               *regexp.Regexp
	matchRegex                *regexp.Regexp
	VHost                     bool
	VHostInput                bool
	Smuggling                 bool
	ExtractTitle              bool
	StatusCode                bool
	Location                  bool
	ContentLength             bool
	FollowRedirects           bool
	RespectHSTS               bool
	StoreResponse             bool
	JSONOutput                bool
	CSVOutput                 bool
	CSVOutputEncoding         string
	PdcpAuth                  string
	Silent                    bool
	Version                   bool
	Verbose                   bool
	NoColor                   bool
	OutputServerHeader        bool
	OutputWebSocket           bool
	ResponseHeadersInStdout   bool
	ResponseInStdout          bool
	Base64ResponseInStdout    bool
	chainInStdout             bool
	FollowHostRedirects       bool
	MaxRedirects              int
	OutputMethod              bool
	TLSProbe                  bool
	CSPProbe                  bool
	OutputContentType         bool
	OutputIP                  bool
	OutputCName               bool
	Unsafe                    bool
	Debug                     bool
	DebugRequests             bool
	DebugResponse             bool
	Pipeline                  bool
	HTTP2Probe                bool
	OutputCDN                 string
	OutputResponseTime        bool
	NoFallback                bool
	NoFallbackScheme          bool
	TechDetect                string
	TLSGrab                   bool
	protocol                  string
	ShowStatistics            bool
	StatsInterval             int
	RandomAgent               bool
	StoreChain                bool
	StoreVisionReconClusters  bool
	Deny                      customlist.CustomList
	Allow                     customlist.CustomList
	MaxResponseBodySizeToSave int
	MaxResponseBodySizeToRead int
	ResponseBodyPreviewSize   int
	OutputExtractRegexs       goflags.StringSlice
	OutputExtractPresets      goflags.StringSlice
	RateLimit                 int
	RateLimitMinute           int
	Probe                     bool
	Resume                    bool
	resumeCfg                 *ResumeCfg
	Exclude                   goflags.StringSlice
	HostMaxErrors             int
	Stream                    bool
	SkipDedupe                bool
	ProbeAllIPS               bool
	Resolvers                 goflags.StringSlice
	Favicon                   bool
	OutputFilterFavicon       goflags.StringSlice
	OutputMatchFavicon        goflags.StringSlice
	LeaveDefaultPorts         bool
	ZTLS                      bool
	OutputLinesCount          bool
	OutputMatchLinesCount     string
	matchLinesCount           []int
	OutputFilterLinesCount    string
	Memprofile                string
	filterLinesCount          []int
	OutputWordsCount          bool
	OutputMatchWordsCount     string
	matchWordsCount           []int
	OutputFilterWordsCount    string
	filterWordsCount          []int
	Hashes                    string
	Jarm                      bool
	Asn                       bool
	OutputMatchCdn            goflags.StringSlice
	OutputFilterCdn           goflags.StringSlice
	SniName                   string
	OutputMatchResponseTime   string
	OutputFilterResponseTime  string
	HealthCheck               bool
	ListDSLVariable           bool
	OutputFilterCondition     string
	OutputMatchCondition      string
	StripFilter               string
	//The OnResult callback function is invoked for each result. It is important to check for errors in the result before using Result.Err.
	OnResult           OnResultCallback
	DisableUpdateCheck bool
	NoDecode           bool
	Screenshot         bool
	UseInstalledChrome bool
	TlsImpersonate     bool
	DisableStdin       bool
	NoScreenshotBytes  bool
	NoHeadlessBody     bool
	ScreenshotTimeout  int
	// HeadlessOptionalArguments specifies optional arguments to pass to Chrome
	HeadlessOptionalArguments goflags.StringSlice
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}
	var cfgFile string

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`httpx 是一个快速且多用途的 HTTP 工具包，允许使用 retryablehttp 库运行多个探针。`)

	flagSet.CreateGroup("input", "输入",
		flagSet.StringVarP(&options.InputFile, "list", "l", "", "包含要处理的主机列表的输入文件"),
		flagSet.StringVarP(&options.InputRawRequest, "request", "rr", "", "包含原始请求的文件"),
		flagSet.StringSliceVarP(&options.InputTargetHost, "target", "u", nil, "要探测的输入目标主机(s)", goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("Probes", "探针",
		flagSet.BoolVarP(&options.StatusCode, "status-code", "sc", false, "显示响应状态码"),
		flagSet.BoolVarP(&options.ContentLength, "content-length", "cl", false, "显示响应内容长度"),
		flagSet.BoolVarP(&options.OutputContentType, "content-type", "ct", false, "显示响应内容类型"),
		flagSet.BoolVar(&options.Location, "location", false, "显示响应重定向位置"),
		flagSet.BoolVar(&options.Favicon, "favicon", false, "显示 '/favicon.ico' 文件的 mmh3 哈希"),
		flagSet.StringVar(&options.Hashes, "hash", "", "显示响应体哈希（支持的：md5,mmh3,simhash,sha1,sha256,sha512)"),
		flagSet.BoolVar(&options.Jarm, "jarm", false, "显示 jarm 指纹哈希"),
		flagSet.BoolVarP(&options.OutputResponseTime, "response-time", "rt", false, "显示响应时间"),
		flagSet.BoolVarP(&options.OutputLinesCount, "line-count", "lc", false, "显示响应体行数"),
		flagSet.BoolVarP(&options.OutputWordsCount, "word-count", "wc", false, "显示响应体字数"),
		flagSet.BoolVar(&options.ExtractTitle, "title", false, "显示页面标题"),
		flagSet.DynamicVarP(&options.ResponseBodyPreviewSize, "body-preview", "bp", 100, "显示响应体的前 N 个字符"),
		flagSet.BoolVarP(&options.OutputServerHeader, "web-server", "server", false, "显示服务器名称"),
		flagSet.DynamicVarP(&options.TechDetect, "tech-detect", "td", "true", "显示基于 wappalyzer 数据集使用的技术分析"),
		flagSet.BoolVar(&options.OutputMethod, "method", false, "显示 HTTP 请求方法"),
		flagSet.BoolVar(&options.OutputWebSocket, "websocket", false, "显示使用 WebSocket 的服务器"),
		flagSet.BoolVar(&options.OutputIP, "ip", false, "显示主机 IP"),
		flagSet.BoolVar(&options.OutputCName, "cname", false, "显示主机 cname"),
		flagSet.BoolVar(&options.Asn, "asn", false, "显示主机 asn 信息"),
		flagSet.DynamicVar(&options.OutputCDN, "cdn", "true", "显示使用的 CDN/WAF"),
		flagSet.BoolVar(&options.Probe, "probe", false, "显示探针状态"),
	)

	flagSet.CreateGroup("headless", "无头模式",
		flagSet.BoolVarP(&options.Screenshot, "screenshot", "ss", false, "使用无头浏览器启用保存页面截图"),
		flagSet.BoolVar(&options.UseInstalledChrome, "system-chrome", false, "启用使用本地安装的 Chrome 进行截图"),
		flagSet.StringSliceVarP(&options.HeadlessOptionalArguments, "headless-options", "ho", nil, "使用附加选项启动无头 Chrome", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&options.NoScreenshotBytes, "exclude-screenshot-bytes", "esb", false, "启用从 JSON 输出中排除截图字节"),
		flagSet.BoolVarP(&options.NoHeadlessBody, "exclude-headless-body", "ehb", false, "启用从 JSON 输出中排除无头标题"),
		flagSet.IntVarP(&options.ScreenshotTimeout, "screenshot-timeout", "st", 10, "设置截图超时时间（秒）"),
	)

	flagSet.CreateGroup("matchers", "匹配器",
		flagSet.StringVarP(&options.OutputMatchStatusCode, "match-code", "mc", "", "匹配指定状态码的响应 (-mc 200,302)"),
		flagSet.StringVarP(&options.OutputMatchContentLength, "match-length", "ml", "", "匹配指定内容长度的响应 (-ml 100,102)"),
		flagSet.StringVarP(&options.OutputMatchLinesCount, "match-line-count", "mlc", "", "匹配指定行数的响应体 (-mlc 423,532)"),
		flagSet.StringVarP(&options.OutputMatchWordsCount, "match-word-count", "mwc", "", "匹配指定字数的响应体 (-mwc 43,55)"),
		flagSet.StringSliceVarP(&options.OutputMatchFavicon, "match-favicon", "mfc", nil, "匹配指定 favicon 哈希的响应 (-mfc 1494302000)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.OutputMatchString, "match-string", "ms", "", "匹配指定字符串的响应 (-ms admin)"),
		flagSet.StringVarP(&options.OutputMatchRegex, "match-regex", "mr", "", "匹配指定正则表达式的响应 (-mr admin)"),
		flagSet.StringSliceVarP(&options.OutputMatchCdn, "match-cdn", "mcdn", nil, fmt.Sprintf("匹配指定 CDN 提供商的主机 (%s)", cdncheck.DefaultCDNProviders), goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.OutputMatchResponseTime, "match-response-time", "mrt", "", "匹配指定响应时间的响应（秒）(-mrt '< 1')"),
		flagSet.StringVarP(&options.OutputMatchCondition, "match-condition", "mdc", "", "使用 DSL 表达式条件匹配响应"),
	)

	flagSet.CreateGroup("extractor", "提取器",
		flagSet.StringSliceVarP(&options.OutputExtractRegexs, "extract-regex", "er", nil, "显示匹配正则表达式响应内容", goflags.StringSliceOptions),
		flagSet.StringSliceVarP(&options.OutputExtractPresets, "extract-preset", "ep", nil, fmt.Sprintf("显示由预定义正则表达式匹配的响应内容 (%s)", strings.Join(maps.Keys(customextract.ExtractPresets), ",")), goflags.StringSliceOptions),
	)

	flagSet.CreateGroup("filters", "过滤器",
		flagSet.StringVarP(&options.OutputFilterStatusCode, "filter-code", "fc", "", "使用指定状态码过滤响应 (-fc 403,401)"),
		flagSet.BoolVarP(&options.OutputFilterErrorPage, "filter-error-page", "fep", false, "使用基于 ML 的错误页面检测过滤响应"),
		flagSet.StringVarP(&options.OutputFilterContentLength, "filter-length", "fl", "", "使用指定内容长度过滤响应 (-fl 23,33)"),
		flagSet.StringVarP(&options.OutputFilterLinesCount, "filter-line-count", "flc", "", "使用指定行数过滤响应体 (-flc 423,532)"),
		flagSet.StringVarP(&options.OutputFilterWordsCount, "filter-word-count", "fwc", "", "使用指定字数过滤响应体 (-fwc 423,532)"),
		flagSet.StringSliceVarP(&options.OutputFilterFavicon, "filter-favicon", "ffc", nil, "使用指定 favicon 哈希过滤响应 (-ffc 1494302000)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.OutputFilterString, "filter-string", "fs", "", "使用指定字符串过滤响应 (-fs admin)"),
		flagSet.StringVarP(&options.OutputFilterRegex, "filter-regex", "fe", "", "使用指定正则表达式过滤响应 (-fe admin)"),
		flagSet.StringSliceVarP(&options.OutputFilterCdn, "filter-cdn", "fcdn", nil, fmt.Sprintf("使用指定 CDN 提供商过滤主机 (%s)", cdncheck.DefaultCDNProviders), goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.OutputFilterResponseTime, "filter-response-time", "frt", "", "使用指定响应时间（秒）过滤响应 (-frt '> 1')"),
		flagSet.StringVarP(&options.OutputFilterCondition, "filter-condition", "fdc", "", "使用 DSL 表达式条件过滤响应"),
		flagSet.DynamicVar(&options.StripFilter, "strip", "html", "剥离响应中的所有标签。支持的格式：html,xml"),
	)

	flagSet.CreateGroup("rate-limit", "速率限制",
		flagSet.IntVarP(&options.Threads, "threads", "t", 50, "使用的线程数"),
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "每秒发送的最大请求数"),
		flagSet.IntVarP(&options.RateLimitMinute, "rate-limit-minute", "rlm", 0, "每分钟发送的最大请求数"),
	)

	flagSet.CreateGroup("Misc", "杂项",
		flagSet.BoolVarP(&options.ProbeAllIPS, "probe-all-ips", "pa", false, "探测与同一主机关联的所有 IP"),
		flagSet.VarP(&options.CustomPorts, "ports", "p", "要探测的端口（nmap 语法：例如 http:1,2-10,11,https:80）"),
		flagSet.StringVar(&options.RequestURIs, "path", "", "要探测的路径或路径列表（逗号分隔，文件）"),
		flagSet.BoolVar(&options.TLSProbe, "tls-probe", false, "在提取的 TLS 域（dns_name）上发送 HTTP 探测"),
		flagSet.BoolVar(&options.CSPProbe, "csp-probe", false, "在提取的 CSP 域上发送 HTTP 探测"),
		flagSet.BoolVar(&options.TLSGrab, "tls-grab", false, "执行 TLS(SSL) 数据抓取"),
		flagSet.BoolVar(&options.Pipeline, "pipeline", false, "探测并显示支持 HTTP1.1 管道的服务器"),
		flagSet.BoolVar(&options.HTTP2Probe, "http2", false, "探测并显示支持 HTTP2 的服务器"),
		flagSet.BoolVar(&options.VHost, "vhost", false, "探测并显示支持 VHOST 的服务器"),
		flagSet.BoolVarP(&options.ListDSLVariable, "list-dsl-variables", "ldv", false, "列出支持 dsl 匹配器/过滤器的 JSON 输出字段键名"),
	)

	flagSet.CreateGroup("update", "更新",
		flagSet.CallbackVarP(GetUpdateCallback(), "update", "up", "更新 httpx 到最新版本"),
		flagSet.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "禁用自动 httpx 更新检查"),
	)

	flagSet.CreateGroup("output", "输出",
		flagSet.StringVarP(&options.Output, "output", "o", "", "写入输出结果的文件"),
		flagSet.BoolVarP(&options.OutputAll, "output-all", "oa", false, "以所有格式写入输出结果的文件名"),
		flagSet.BoolVarP(&options.StoreResponse, "store-response", "sr", false, "将 HTTP 响应存储到输出目录"),
		flagSet.StringVarP(&options.StoreResponseDir, "store-response-dir", "srd", "", "将 HTTP 响应存储到自定义目录"),
		flagSet.BoolVar(&options.CSVOutput, "csv", false, "以 csv 格式存储输出"),
		flagSet.StringVarP(&options.CSVOutputEncoding, "csv-output-encoding", "csvo", "", "定义输出编码"),
		flagSet.BoolVarP(&options.JSONOutput, "json", "j", false, "以 JSONL(ines) 格式存储输出"),
		flagSet.BoolVarP(&options.ResponseHeadersInStdout, "include-response-header", "irh", false, "在 JSON 输出中包含 HTTP 响应（头）(仅 -json)"),
		flagSet.BoolVarP(&options.ResponseInStdout, "include-response", "irr", false, "在 JSON 输出中包含 HTTP 请求/响应（头 + 正文）(仅 -json)"),
		flagSet.BoolVarP(&options.Base64ResponseInStdout, "include-response-base64", "irrb", false, "在 JSON 输出中包含 base64 编码的 HTTP 请求/响应（仅 -json)"),
		flagSet.BoolVar(&options.chainInStdout, "include-chain", false, "在 JSON 输出中包含重定向 HTTP 链（仅 -json)"),
		flagSet.BoolVar(&options.StoreChain, "store-chain", false, "在响应中包含 HTTP 重定向链（仅 -sr)"),
		flagSet.BoolVarP(&options.StoreVisionReconClusters, "store-vision-recon-cluster", "svrc", false, "包含视觉侦察群集（仅 -ss 和 -sr)"),
	)

	flagSet.CreateGroup("configs", "配置",
		flagSet.StringVar(&cfgFile, "config", "", "httpx 配置文件的路径（默认 $HOME/.config/httpx/config.yaml）"),
		flagSet.DynamicVar(&options.PdcpAuth, "auth", "true", "配置 projectdiscovery 云 (pdcp) API 密钥"),
		flagSet.StringSliceVarP(&options.Resolvers, "resolvers", "r", nil, "自定义解析器列表（文件或逗号分隔）", goflags.NormalizedStringSliceOptions),
		flagSet.Var(&options.Allow, "allow", "要处理的 IP/CIDR 允许列表（文件或逗号分隔）"),
		flagSet.Var(&options.Deny, "deny", "要处理的 IP/CIDR 拒绝列表（文件或逗号分隔）"),
		flagSet.StringVarP(&options.SniName, "sni-name", "sni", "", "自定义 TLS SNI 名称"),
		flagSet.BoolVar(&options.RandomAgent, "random-agent", true, "启用随机 User-Agent"),
		flagSet.VarP(&options.CustomHeaders, "header", "H", "随请求发送的自定义 HTTP 头"),
		flagSet.StringVarP(&options.HTTPProxy, "proxy", "http-proxy", "", "要使用的 HTTP 代理 (例如 http://127.0.0.1:8080)"),
		flagSet.BoolVar(&options.Unsafe, "unsafe", false, "发送原始请求，跳过 golang 标准化"),
		flagSet.BoolVar(&options.Resume, "resume", false, "使用 resume.cfg 恢复扫描"),
		flagSet.BoolVarP(&options.FollowRedirects, "follow-redirects", "fr", false, "跟随 HTTP 重定向"),
		flagSet.IntVarP(&options.MaxRedirects, "max-redirects", "maxr", 10, "每个主机要跟随的最大重定向数"),
		flagSet.BoolVarP(&options.FollowHostRedirects, "follow-host-redirects", "fhr", false, "跟随同一主机的重定向"),
		flagSet.BoolVarP(&options.RespectHSTS, "respect-hsts", "rhsts", false, "尊重重定向请求的 HSTS 响应头"),
		flagSet.BoolVar(&options.VHostInput, "vhost-input", false, "将 vhost 列表作为输入获取"),
		flagSet.StringVar(&options.Methods, "x", "", "要探测的请求方法，使用 'all' 探测所有 HTTP 方法"),
		flagSet.StringVar(&options.RequestBody, "body", "", "要在 HTTP 请求中包含的 POST 正文"),
		flagSet.BoolVarP(&options.Stream, "stream", "s", false, "流模式 - 在不排序的情况下开始处理输入目标"),
		flagSet.BoolVarP(&options.SkipDedupe, "skip-dedupe", "sd", false, "禁用去重复输入项（仅与流模式一起使用）"),
		flagSet.BoolVarP(&options.LeaveDefaultPorts, "leave-default-ports", "ldp", false, "在主机头中保留默认的 http/https 端口 (例如 http://host:80 - https://host:443)"),
		flagSet.BoolVar(&options.ZTLS, "ztls", false, "使用 ztls 库，并自动回退到 tls13 的标准库"),
		flagSet.BoolVar(&options.NoDecode, "no-decode", false, "避免解码正文"),
		flagSet.BoolVarP(&options.TlsImpersonate, "tls-impersonate", "tlsi", false, "启用实验性的客户端 hello (ja3) tls 随机化"),
		flagSet.BoolVar(&options.DisableStdin, "no-stdin", false, "禁用 Stdin 处理"),
	)

	flagSet.CreateGroup("debug", "调试",
		flagSet.BoolVarP(&options.HealthCheck, "hc", "health-check", false, "运行诊断检查"),
		flagSet.BoolVar(&options.Debug, "debug", false, "在命令行界面显示请求/响应内容"),
		flagSet.BoolVar(&options.DebugRequests, "debug-req", false, "在命令行界面显示请求内容"),
		flagSet.BoolVar(&options.DebugResponse, "debug-resp", false, "在命令行界面显示响应内容"),
		flagSet.BoolVar(&options.Version, "version", false, "显示 httpx 版本"),
		flagSet.BoolVar(&options.ShowStatistics, "stats", false, "显示扫描统计信息"),
		flagSet.StringVar(&options.Memprofile, "profile-mem", "", "可选的 httpx 内存配置文件转储文件"),
		flagSet.BoolVar(&options.Silent, "silent", false, "静音模式"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "详细模式"),
		flagSet.IntVarP(&options.StatsInterval, "stats-interval", "si", 0, "显示统计信息更新之间的等待秒数（默认：5）"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "禁用命令行输出中的颜色"),
	)

	flagSet.CreateGroup("Optimizations", "优化",
		flagSet.BoolVarP(&options.NoFallback, "no-fallback", "nf", false, "显示探测到的协议（HTTPS 和 HTTP）"),
		flagSet.BoolVarP(&options.NoFallbackScheme, "no-fallback-scheme", "nfs", false, "使用输入中指定的协议方案进行探测"),
		flagSet.IntVarP(&options.HostMaxErrors, "max-host-error", "maxhr", 30, "在跳过剩余路径之前每个主机允许的最大错误数"),
		flagSet.StringSliceVarP(&options.Exclude, "exclude", "e", nil, "排除与指定过滤器匹配的主机 ('cdn', 'private-ips', cidr, ip, regex)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.IntVar(&options.Retries, "retries", 0, "重试次数"),
		flagSet.IntVar(&options.Timeout, "timeout", 10, "超时时间（秒）"),
		flagSet.DurationVar(&options.Delay, "delay", -1, "每个 HTTP 请求之间的持续时间（例如：200ms, 1s）"),
		flagSet.IntVarP(&options.MaxResponseBodySizeToSave, "response-size-to-save", "rsts", math.MaxInt32, "以字节为单位保存的最大响应大小"),
		flagSet.IntVarP(&options.MaxResponseBodySizeToRead, "response-size-to-read", "rstr", math.MaxInt32, "以字节为单位读取的最大响应大小"),
	)

	_ = flagSet.Parse()

	if options.OutputAll && options.Output == "" {
		gologger.Fatal().Msg("Please specify an output file using -o/-output when using -oa/-output-all")
	}

	if options.OutputAll {
		options.JSONOutput = true
		options.CSVOutput = true
	}

	if cfgFile != "" {
		if !fileutil.FileExists(cfgFile) {
			gologger.Fatal().Msgf("given config file '%s' does not exist", cfgFile)
		}
		// merge config file with flags
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}

	// api key hierarchy: cli flag > env var > .pdcp/credential file
	if options.PdcpAuth == "true" {
		AuthWithPDCP()
	} else if len(options.PdcpAuth) == 36 {
		PDCPApiKey = options.PdcpAuth
		ph := pdcp.PDCPCredHandler{}
		if _, err := ph.GetCreds(); err == pdcp.ErrNoCreds {
			apiServer := env.GetEnvOrDefault("PDCP_API_SERVER", pdcp.DefaultApiServer)
			if validatedCreds, err := ph.ValidateAPIKey(PDCPApiKey, apiServer, "httpx"); err == nil {
				_ = ph.SaveCreds(validatedCreds)
			}
		}
	}

	if options.HealthCheck {
		gologger.Print().Msgf("%s\n", DoHealthCheck(options, flagSet))
		os.Exit(0)
	}

	if options.StatsInterval != 0 {
		options.ShowStatistics = true
	}

	if options.ResponseBodyPreviewSize > 0 && options.StripFilter == "" {
		options.StripFilter = "html"
	}

	// Read the inputs and configure the logging
	options.configureOutput()

	err := options.configureResume()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}
	if options.ListDSLVariable {
		dslVars, err := dslVariables()
		if err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
		for _, dsl := range dslVars {
			gologger.Print().Msg(dsl)
		}
		os.Exit(0)
	}
	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", version)
		os.Exit(0)
	}

	if !options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("httpx", version)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("httpx version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current httpx version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	if err := options.ValidateOptions(); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	return options
}

func (options *Options) ValidateOptions() error {
	if options.InputFile != "" && !fileutilz.FileNameIsGlob(options.InputFile) && !fileutil.FileExists(options.InputFile) {
		return fmt.Errorf("file '%s' does not exist", options.InputFile)
	}

	if options.InputRawRequest != "" && !fileutil.FileExists(options.InputRawRequest) {
		return fmt.Errorf("file '%s' does not exist", options.InputRawRequest)
	}

	if options.Silent {
		incompatibleFlagsList := flagsIncompatibleWithSilent(options)
		if len(incompatibleFlagsList) > 0 {
			last := incompatibleFlagsList[len(incompatibleFlagsList)-1]
			first := incompatibleFlagsList[:len(incompatibleFlagsList)-1]
			msg := ""
			if len(incompatibleFlagsList) > 1 {
				msg += fmt.Sprintf("%s and %s flags are", strings.Join(first, ", "), last)
			} else {
				msg += fmt.Sprintf("%s flag is", last)
			}
			msg += " incompatible with silent flag"
			return fmt.Errorf(msg)
		}
	}

	var err error
	if options.matchStatusCode, err = stringz.StringToSliceInt(options.OutputMatchStatusCode); err != nil {
		return errors.Wrap(err, "Invalid value for match status code option")
	}
	if options.matchContentLength, err = stringz.StringToSliceInt(options.OutputMatchContentLength); err != nil {
		return errors.Wrap(err, "Invalid value for match content length option")
	}
	if options.filterStatusCode, err = stringz.StringToSliceInt(options.OutputFilterStatusCode); err != nil {
		return errors.Wrap(err, "Invalid value for filter status code option")
	}
	if options.filterContentLength, err = stringz.StringToSliceInt(options.OutputFilterContentLength); err != nil {
		return errors.Wrap(err, "Invalid value for filter content length option")
	}
	if options.OutputFilterRegex != "" {
		if options.filterRegex, err = regexp.Compile(options.OutputFilterRegex); err != nil {
			return errors.Wrap(err, "Invalid value for regex filter option")
		}
	}
	if options.OutputMatchRegex != "" {
		if options.matchRegex, err = regexp.Compile(options.OutputMatchRegex); err != nil {
			return errors.Wrap(err, "Invalid value for match regex option")
		}
	}
	if options.matchLinesCount, err = stringz.StringToSliceInt(options.OutputMatchLinesCount); err != nil {
		return errors.Wrap(err, "Invalid value for match lines count option")
	}
	if options.matchWordsCount, err = stringz.StringToSliceInt(options.OutputMatchWordsCount); err != nil {
		return errors.Wrap(err, "Invalid value for match words count option")
	}
	if options.filterLinesCount, err = stringz.StringToSliceInt(options.OutputFilterLinesCount); err != nil {
		return errors.Wrap(err, "Invalid value for filter lines count option")
	}
	if options.filterWordsCount, err = stringz.StringToSliceInt(options.OutputFilterWordsCount); err != nil {
		return errors.Wrap(err, "Invalid value for filter words count option")
	}

	var resolvers []string
	for _, resolver := range options.Resolvers {
		if fileutil.FileExists(resolver) {
			chFile, err := fileutil.ReadFile(resolver)
			if err != nil {
				return errors.Wrapf(err, "Couldn't process resolver file \"%s\"", resolver)
			}
			for line := range chFile {
				resolvers = append(resolvers, line)
			}
		} else {
			resolvers = append(resolvers, resolver)
		}
	}

	options.Resolvers = resolvers
	if len(options.Resolvers) > 0 {
		gologger.Debug().Msgf("Using resolvers: %s\n", strings.Join(options.Resolvers, ","))
	}

	if options.Screenshot && !options.StoreResponse {
		gologger.Debug().Msgf("automatically enabling store response")
		options.StoreResponse = true
	}
	if options.StoreResponse && options.StoreResponseDir == "" {
		gologger.Debug().Msgf("Store response directory not specified, using \"%s\"\n", DefaultOutputDirectory)
		options.StoreResponseDir = DefaultOutputDirectory
	}
	if options.StoreResponseDir != "" && !options.StoreResponse {
		gologger.Debug().Msgf("Store response directory specified, enabling \"sr\" flag automatically\n")
		options.StoreResponse = true
	}

	if options.Hashes != "" {
		for _, hashType := range strings.Split(options.Hashes, ",") {
			if !slice.StringSliceContains([]string{"md5", "sha1", "sha256", "sha512", "mmh3", "simhash"}, strings.ToLower(hashType)) {
				gologger.Error().Msgf("Unsupported hash type: %s\n", hashType)
			}
		}
	}
	if len(options.OutputMatchCdn) > 0 || len(options.OutputFilterCdn) > 0 {
		options.OutputCDN = "true"
	}

	return nil
}

// redundant with katana
func (options *Options) ParseHeadlessOptionalArguments() map[string]string {
	var (
		lastKey           string
		optionalArguments = make(map[string]string)
	)
	for _, v := range options.HeadlessOptionalArguments {
		if v == "" {
			continue
		}
		if argParts := strings.SplitN(v, "=", 2); len(argParts) >= 2 {
			key := strings.TrimSpace(argParts[0])
			value := strings.TrimSpace(argParts[1])
			if key != "" && value != "" {
				optionalArguments[key] = value
				lastKey = key
			}
		} else if !strings.HasPrefix(v, "--") {
			optionalArguments[lastKey] += "," + v
		} else {
			optionalArguments[v] = ""
		}
	}
	return optionalArguments
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
	if len(options.OutputMatchResponseTime) > 0 || len(options.OutputFilterResponseTime) > 0 {
		options.OutputResponseTime = true
	}
	if options.CSVOutputEncoding != "" {
		options.CSVOutput = true
	}
}

func (options *Options) configureResume() error {
	options.resumeCfg = &ResumeCfg{}
	if options.Resume && fileutil.FileExists(DefaultResumeFile) {
		return goconfig.Load(&options.resumeCfg, DefaultResumeFile)

	}
	return nil
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume && fileutil.FileExists(DefaultResumeFile)
}

// ShouldSaveResume file
func (options *Options) ShouldSaveResume() bool {
	return true
}

func flagsIncompatibleWithSilent(options *Options) []string {
	var incompatibleFlagsList []string
	for k, v := range map[string]bool{
		"debug":          options.Debug,
		"debug-request":  options.DebugRequests,
		"debug-response": options.DebugResponse,
		"verbose":        options.Verbose,
	} {
		if v {
			incompatibleFlagsList = append(incompatibleFlagsList, k)
		}
	}
	return incompatibleFlagsList
}
