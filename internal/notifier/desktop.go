package notifier

import (
	"github.com/gen2brain/beeep"
)

type DesktopNotifier struct{}

func NewDesktopNotifier() *DesktopNotifier {
	return &DesktopNotifier{}
}

func (d *DesktopNotifier) Send(event Event) error {
	title := "Pinakastra"

	switch event.Type {
	case ScanStart:
		title = "🚀 Scan Started"
	case ScanComplete:
		title = "✅ Scan Complete"
	case Critical:
		title = "🚨 Critical Finding"
	case Error:
		title = "❌ Error"
	}

	message := event.Message
	if event.Domain != "" {
		message = event.Domain + ": " + message
	}

	return beeep.Notify(title, message, "")
}
