package notifier

import (
	"fmt"
	"time"

	"github.com/who0xac/pinakastra/internal/config"
)

type Notifier struct {
	cfg      *config.Config
	telegram *TelegramNotifier
	desktop  *DesktopNotifier
}

func New(cfg *config.Config) *Notifier {
	n := &Notifier{
		cfg:     cfg,
		desktop: NewDesktopNotifier(),
	}

	if cfg.APIKeys.TelegramBotToken != "" && cfg.APIKeys.TelegramChatID != "" {
		n.telegram = NewTelegramNotifier(cfg.APIKeys.TelegramBotToken, cfg.APIKeys.TelegramChatID)
	}

	return n
}

func (n *Notifier) SendStart(domain string) {
	message := fmt.Sprintf("🎯 Starting reconnaissance on %s", domain)

	// Send to Telegram
	if n.cfg.Notifications.Telegram && n.telegram != nil {
		go n.telegram.SendMessage(message)
	}

	// Send desktop notification
	if n.cfg.Notifications.Desktop {
		go n.desktop.Notify("Pinakastra - Scan Started", message)
	}
}

func (n *Notifier) SendComplete(domain string, duration time.Duration) {
	message := fmt.Sprintf("✅ Scan completed for %s in %s", domain, duration.Round(time.Second))

	// Send to Telegram
	if n.cfg.Notifications.Telegram && n.telegram != nil {
		go n.telegram.SendMessage(message)
	}

	// Send desktop notification
	if n.cfg.Notifications.Desktop {
		go n.desktop.Notify("Pinakastra - Scan Complete", message)
	}
}

func (n *Notifier) SendCritical(domain, finding string) {
	message := fmt.Sprintf("🚨 CRITICAL: %s found on %s", finding, domain)

	// Send to Telegram
	if n.cfg.Notifications.Telegram && n.telegram != nil {
		go n.telegram.SendMessage(message)
	}

	// Send desktop notification
	if n.cfg.Notifications.Desktop {
		go n.desktop.Notify("Pinakastra - Critical Finding", message)
	}
}

func (n *Notifier) SendError(domain, errorMsg string) {
	message := fmt.Sprintf("❌ Error on %s: %s", domain, errorMsg)

	// Send to Telegram
	if n.cfg.Notifications.Telegram && n.telegram != nil {
		go n.telegram.SendMessage(message)
	}
}

func (n *Notifier) SendFile(filePath, caption string) error {
	if n.telegram == nil {
		return nil
	}
	return n.telegram.SendFile(filePath, caption)
}
