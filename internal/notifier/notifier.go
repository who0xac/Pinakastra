package notifier

import (
	"github.com/who0xac/pinakastra/internal/config"
	"github.com/who0xac/pinakastra/internal/websocket"
)

type EventType string

const (
	ScanStart    EventType = "scan_start"
	ScanComplete EventType = "scan_complete"
	Critical     EventType = "critical"
	Error        EventType = "error"
	Info         EventType = "info"
)

type Event struct {
	Type    EventType
	Domain  string
	Message string
	Data    interface{}
}

type Notifier struct {
	cfg      *config.Config
	telegram *TelegramNotifier
	desktop  *DesktopNotifier
	hub      *websocket.Hub
}

func New(cfg *config.Config, hub *websocket.Hub) *Notifier {
	n := &Notifier{
		cfg:     cfg,
		hub:     hub,
		desktop: NewDesktopNotifier(),
	}

	if cfg.APIKeys.TelegramBotToken != "" && cfg.APIKeys.TelegramChatID != "" {
		n.telegram = NewTelegramNotifier(cfg.APIKeys.TelegramBotToken, cfg.APIKeys.TelegramChatID)
	}

	return n
}

func (n *Notifier) Send(event Event) {
	// Check if this event type should be notified
	if !n.shouldNotify(event.Type) {
		return
	}

	// Send to WebSocket
	n.hub.Broadcast(websocket.Message{
		Type: string(event.Type),
		Data: map[string]interface{}{
			"domain":  event.Domain,
			"message": event.Message,
		},
	})

	// Send to Telegram
	if n.cfg.Notifications.Telegram && n.telegram != nil {
		go n.telegram.Send(event)
	}

	// Send desktop notification
	if n.cfg.Notifications.Desktop {
		go n.desktop.Send(event)
	}
}

func (n *Notifier) SendFile(domain, filePath, caption string) error {
	if !n.cfg.Notifications.SendFiles || n.telegram == nil {
		return nil
	}

	return n.telegram.SendFile(filePath, caption)
}

func (n *Notifier) shouldNotify(eventType EventType) bool {
	switch eventType {
	case ScanStart:
		return n.cfg.Notifications.OnStart
	case ScanComplete:
		return n.cfg.Notifications.OnComplete
	case Critical:
		return n.cfg.Notifications.OnCritical
	case Error:
		return n.cfg.Notifications.OnError
	default:
		return true
	}
}
