package services

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"runtime/debug"
	"strconv"

	"github.com/snail007/goproxy/utils"
)

type Config struct {
	AllowedDomains []string `json:"allowedDomains"`
}

var config Config

// 加载配置文件
func loadConfig(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	byteValue, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		return err
	}

	return nil
}

// 检查给定的域名是否在白名单中
func isDomainAllowed(domain string) bool {
	for _, allowedDomain := range config.AllowedDomains {
		if strings.Contains(domain, allowedDomain) {
			return true
		}
	}
	return false
}

type HTTP struct {
	outPool   utils.OutPool
	cfg       HTTPArgs
	checker   utils.Checker
	basicAuth utils.BasicAuth
}

func NewHTTP() Service {
	return &HTTP{
		outPool:   utils.OutPool{},
		cfg:       HTTPArgs{},
		checker:   utils.Checker{},
		basicAuth: utils.BasicAuth{},
	}
}

func (s *HTTP) InitService() {
	s.InitBasicAuth()
	if *s.cfg.Parent != "" {
		s.checker = utils.NewChecker(*s.cfg.HTTPTimeout, int64(*s.cfg.Interval), *s.cfg.Blocked, *s.cfg.Direct)
	}
}

func (s *HTTP) StopService() {
	if s.outPool.Pool != nil {
		s.outPool.Pool.ReleaseAll()
	}
}

func (s *HTTP) Start(args interface{}) (err error) {
	// 加载配置文件
	err = loadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config file: %v", err)
		return err
	}

	s.cfg = args.(HTTPArgs)
	if *s.cfg.Parent != "" {
		log.Printf("use %s parent %s", *s.cfg.ParentType, *s.cfg.Parent)
		s.InitOutConnPool()
	}

	s.InitService()

	host, port, _ := net.SplitHostPort(*s.cfg.Local)
	p, _ := strconv.Atoi(port)
	sc := utils.NewServerChannel(host, p)
	if *s.cfg.LocalType == TYPE_TCP {
		err = sc.ListenTCP(s.callback)
	} else {
		err = sc.ListenTls(s.cfg.CertBytes, s.cfg.KeyBytes, s.callback)
	}
	if err != nil {
		return err
	}
	log.Printf("%s http(s) proxy on %s", *s.cfg.LocalType, (*sc.Listener).Addr())
	return nil
}

func (s *HTTP) Clean() {
	s.StopService()
}

func (s *HTTP) callback(inConn net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("http(s) conn handler crashed with err : %s \nstack: %s", err, string(debug.Stack()))
		}
	}()
	req, err := utils.NewHTTPRequest(&inConn, 4096, s.IsBasicAuth(), &s.basicAuth)
	if err != nil {
		if err != io.EOF {
			log.Printf("decoder error , form %s, ERR:%s", err, inConn.RemoteAddr())
		}
		utils.CloseConn(&inConn)
		return
	}
	address := req.Host

	// 获取Referer头部
	referer, err := req.GetHeader("Referer")
	if err != nil {
		referer = "" // 如果找不到Referer头部，则设为空字符串
	}

	// 检查Referer是否包含im30.net
	if !strings.Contains(referer, "im30.net") && !isDomainAllowed(address) {
		log.Printf("domain not allowed: %s, referer: %s", address, referer)
		// 使用直接写出响应方式发送错误
		inConn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nForbidden"))
		utils.CloseConn(&inConn)
		return
	}

	useProxy := true
	if *s.cfg.Parent == "" {
		useProxy = false
	} else if *s.cfg.Always {
		useProxy = true
	} else {
		if req.IsHTTPS() {
			s.checker.Add(address, true, req.Method, "", nil)
		} else {
			s.checker.Add(address, false, req.Method, req.URL, req.HeadBuf)
		}
		useProxy, _, _ = s.checker.IsBlocked(req.Host)
	}
	log.Printf("use proxy : %v, %s", useProxy, address)
	err = s.OutToTCP(useProxy, address, &inConn, &req)
	if err != nil {
		if *s.cfg.Parent == "" {
			log.Printf("connect to %s fail, ERR:%s", address, err)
		} else {
			log.Printf("connect to %s parent %s fail", *s.cfg.ParentType, *s.cfg.Parent)
		}
		utils.CloseConn(&inConn)
	}
}

func (s *HTTP) OutToTCP(useProxy bool, address string, inConn *net.Conn, req *utils.HTTPRequest) (err error) {
	inAddr := (*inConn).RemoteAddr().String()
	inLocalAddr := (*inConn).LocalAddr().String()
	if s.IsDeadLoop(inLocalAddr, req.Host) {
		utils.CloseConn(inConn)
		err = fmt.Errorf("dead loop detected, %s", req.Host)
		return err
	}
	var outConn net.Conn
	var _outConn interface{}
	if useProxy {
		_outConn, err = s.outPool.Pool.Get()
		if err == nil {
			outConn = _outConn.(net.Conn)
		}
	} else {
		outConn, err = utils.ConnectHost(address, *s.cfg.Timeout)
	}
	if err != nil {
		log.Printf("connect to %s, err: %s", *s.cfg.Parent, err)
		utils.CloseConn(inConn)
		return err
	}

	outAddr := outConn.RemoteAddr().String()
	outLocalAddr := outConn.LocalAddr().String()

	if req.IsHTTPS() && !useProxy {
		req.HTTPSReply()
	} else {
		outConn.Write(req.HeadBuf)
	}
	utils.IoBind(*inConn, outConn, func(isSrcErr bool, err error) {
		log.Printf("conn %s - %s - %s - %s released [%s]", inAddr, inLocalAddr, outLocalAddr, outAddr, req.Host)
		utils.CloseConn(inConn)
		utils.CloseConn(&outConn)
	}, func(n int, d bool) {}, 0)
	log.Printf("conn %s - %s - %s - %s connected [%s]", inAddr, inLocalAddr, outLocalAddr, outAddr, req.Host)
	return nil
}

func (s *HTTP) OutToUDP(inConn *net.Conn) (err error) {
	return nil
}

func (s *HTTP) InitOutConnPool() {
	if *s.cfg.ParentType == TYPE_TLS || *s.cfg.ParentType == TYPE_TCP {
		s.outPool = utils.NewOutPool(
			*s.cfg.CheckParentInterval,
			*s.cfg.ParentType == TYPE_TLS,
			s.cfg.CertBytes, s.cfg.KeyBytes,
			*s.cfg.Parent,
			*s.cfg.Timeout,
			*s.cfg.PoolSize,
			*s.cfg.PoolSize*2,
		)
	}
}

func (s *HTTP) InitBasicAuth() (err error) {
	s.basicAuth = utils.NewBasicAuth()
	if *s.cfg.AuthFile != "" {
		var n = 0
		n, err = s.basicAuth.AddFromFile(*s.cfg.AuthFile)
		if err != nil {
			err = fmt.Errorf("auth-file ERR:%s", err)
			return err
		}
		log.Printf("auth data added from file %d, total: %d", n, s.basicAuth.Total())
	}
	if len(*s.cfg.Auth) > 0 {
		n := s.basicAuth.Add(*s.cfg.Auth)
		log.Printf("auth data added %d, total: %d", n, s.basicAuth.Total())
	}
	return nil
}

func (s *HTTP) IsBasicAuth() bool {
	return *s.cfg.AuthFile != "" || len(*s.cfg.Auth) > 0
}

func (s *HTTP) IsDeadLoop(inLocalAddr string, host string) bool {
	inIP, inPort, err := net.SplitHostPort(inLocalAddr)
	if err != nil {
		return false
	}
	outDomain, outPort, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	if inPort == outPort {
		var outIPs []net.IP
		outIPs, err = net.LookupIP(outDomain)
		if err == nil {
			for _, ip := range outIPs {
				if ip.String() == inIP {
					return true
				}
			}
		}
		interfaceIPs, err := utils.GetAllInterfaceAddr()
		if err == nil {
			for _, localIP := range interfaceIPs {
				for _, outIP := range outIPs {
					if localIP.Equal(outIP) {
						return true
					}
				}
			}
		}
	}
	return false
}
