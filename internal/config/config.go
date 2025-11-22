package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	APIKeys   APIKeys   `mapstructure:"api_keys"`
	Paths     Paths     `mapstructure:"paths"`
	Storage   Storage   `mapstructure:"storage"`
	WebUI     WebUI     `mapstructure:"webui"`
	Notify    Notify    `mapstructure:"notifications"`
}

type APIKeys struct {
	GitHub    string `mapstructure:"github_token"`
	GitLab    string `mapstructure:"gitlab_token"`
	Shodan    string `mapstructure:"shodan_api_key"`
	Chaos     string `mapstructure:"chaos_api_key"`
	Telegram  string `mapstructure:"telegram_bot_token"`
	ChatID    string `mapstructure:"telegram_chat_id"`
}

type Paths struct {
	Resolvers            string `mapstructure:"resolvers"`
	Subdomains           string `mapstructure:"subdomains_wordlist"`
	Directories          string `mapstructure:"directories_wordlist"`
	DirectoriesWordlist  string `mapstructure:"directories_wordlist"`
	AmassConfig          string `mapstructure:"amass_config"`
	JSAPath              string `mapstructure:"jsa_path"`
}

type Storage struct {
	BasePath string `mapstructure:"base_path"`
}

type WebUI struct {
	Port int `mapstructure:"port"`
}

type Notify struct {
	Telegram bool `mapstructure:"telegram"`
	Desktop  bool `mapstructure:"desktop"`
}

func Load() *Config {
	baseDir := getBaseDir()

	cfg := &Config{
		Paths: Paths{
			Resolvers:           filepath.Join(baseDir, "configs", "resolvers.txt"),
			Subdomains:          filepath.Join(baseDir, "configs", "wordlists", "subdomains.txt"),
			Directories:         filepath.Join(baseDir, "configs", "wordlists", "directories.txt"),
			DirectoriesWordlist: filepath.Join(baseDir, "configs", "wordlists", "directories.txt"),
			AmassConfig:         expandPath("~/.config/amass/config.yaml"),
			JSAPath:             expandPath("~/tools/JSA"),
		},
		Storage: Storage{
			BasePath: expandPath("~/recon-results"),
		},
		WebUI: WebUI{
			Port: 9000,
		},
		Notify: Notify{
			Telegram: false,
			Desktop:  false,
		},
	}

	// Load from env
	cfg.APIKeys.GitHub = os.Getenv("GITHUB_TOKEN")
	cfg.APIKeys.GitLab = os.Getenv("GITLAB_TOKEN")
	cfg.APIKeys.Shodan = os.Getenv("SHODAN_API_KEY")
	cfg.APIKeys.Chaos = os.Getenv("CHAOS_API_KEY")
	cfg.APIKeys.Telegram = os.Getenv("TELEGRAM_BOT_TOKEN")
	cfg.APIKeys.ChatID = os.Getenv("TELEGRAM_CHAT_ID")

	// Override from config file if exists
	if err := viper.Unmarshal(cfg); err == nil {
		cfg.Paths.Resolvers = expandPath(cfg.Paths.Resolvers)
		cfg.Paths.Subdomains = expandPath(cfg.Paths.Subdomains)
		cfg.Paths.Directories = expandPath(cfg.Paths.Directories)
		cfg.Paths.DirectoriesWordlist = expandPath(cfg.Paths.DirectoriesWordlist)
		cfg.Paths.AmassConfig = expandPath(cfg.Paths.AmassConfig)
		cfg.Paths.JSAPath = expandPath(cfg.Paths.JSAPath)
		cfg.Storage.BasePath = expandPath(cfg.Storage.BasePath)
	}

	return cfg
}

func getBaseDir() string {
	// Get executable path
	ex, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(ex)
}

func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		if runtime.GOOS == "windows" {
			return filepath.Join(home, strings.ReplaceAll(path[2:], "/", "\\"))
		}
		return filepath.Join(home, path[2:])
	}
	return path
}

func (c *Config) GetResolvers() string {
	return c.Paths.Resolvers
}

func (c *Config) GetSubdomainsWordlist() string {
	return c.Paths.Subdomains
}

func (c *Config) GetDirectoriesWordlist() string {
	return c.Paths.Directories
}

func (c *Config) GetOutputDir(domain string) string {
	return filepath.Join(c.Storage.BasePath, domain)
}
