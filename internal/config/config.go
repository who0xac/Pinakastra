package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	APIKeys       APIKeys       `mapstructure:"api_keys"`
	Paths         Paths         `mapstructure:"paths"`
	Storage       Storage       `mapstructure:"storage"`
	Notifications Notifications `mapstructure:"notifications"`
}

type APIKeys struct {
	GitHub           string `mapstructure:"github_token"`
	GitLab           string `mapstructure:"gitlab_token"`
	Shodan           string `mapstructure:"shodan_api_key"`
	Chaos            string `mapstructure:"chaos_api_key"`
	TelegramBotToken string `mapstructure:"telegram_bot_token"`
	TelegramChatID   string `mapstructure:"telegram_chat_id"`
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

type Notifications struct {
	Telegram       bool   `mapstructure:"telegram"`
	Desktop        bool   `mapstructure:"desktop"`
	TelegramBotToken string `mapstructure:"telegram_bot_token"`
	TelegramChatID   string `mapstructure:"telegram_chat_id"`
}

func Load() *Config {
	baseDir := getBaseDir()

	cfg := &Config{
		Paths: Paths{
			Resolvers:           expandPath("~/.config/pinakastra/resolvers.txt"),
			Subdomains:          expandPath("~/.config/pinakastra/wordlists/subdomains.txt"),
			Directories:         expandPath("~/.config/pinakastra/wordlists/directories.txt"),
			DirectoriesWordlist: expandPath("~/.config/pinakastra/wordlists/directories.txt"),
			AmassConfig:         expandPath("~/.config/amass/config.yaml"),
			JSAPath:             expandPath("~/tools/JSA"),
		},
		Storage: Storage{
			BasePath: expandPath("~/recon-results"),
		},
		Notifications: Notifications{
			Telegram:         false,
			Desktop:          false,
			TelegramBotToken: "",
			TelegramChatID:   "",
		},
	}

	// Setup viper to read config file
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(expandPath("~/.config/pinakastra"))
	viper.AddConfigPath(".")

	// Load config file if it exists
	if err := viper.ReadInConfig(); err == nil {
		viper.Unmarshal(cfg)
	}

	// Override with environment variables (env takes priority over file)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		cfg.APIKeys.GitHub = token
	}
	if token := os.Getenv("GITLAB_TOKEN"); token != "" {
		cfg.APIKeys.GitLab = token
	}
	if token := os.Getenv("SHODAN_API_KEY"); token != "" {
		cfg.APIKeys.Shodan = token
	}
	if token := os.Getenv("CHAOS_API_KEY"); token != "" {
		cfg.APIKeys.Chaos = token
	}
	if token := os.Getenv("TELEGRAM_BOT_TOKEN"); token != "" {
		cfg.Notifications.TelegramBotToken = token
		cfg.APIKeys.TelegramBotToken = token
	}
	if chatID := os.Getenv("TELEGRAM_CHAT_ID"); chatID != "" {
		cfg.Notifications.TelegramChatID = chatID
		cfg.APIKeys.TelegramChatID = chatID
	}

	// Expand all paths
	cfg.Paths.Resolvers = expandPath(cfg.Paths.Resolvers)
	cfg.Paths.Subdomains = expandPath(cfg.Paths.Subdomains)
	cfg.Paths.Directories = expandPath(cfg.Paths.Directories)
	cfg.Paths.DirectoriesWordlist = expandPath(cfg.Paths.DirectoriesWordlist)
	cfg.Paths.AmassConfig = expandPath(cfg.Paths.AmassConfig)
	cfg.Paths.JSAPath = expandPath(cfg.Paths.JSAPath)
	cfg.Storage.BasePath = expandPath(cfg.Storage.BasePath)

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
