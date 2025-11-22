package notifier

import (
	"github.com/gen2brain/beeep"
)

type DesktopNotifier struct{}

func NewDesktopNotifier() *DesktopNotifier {
	return &DesktopNotifier{}
}

func (d *DesktopNotifier) Notify(title, message string) error {
	return beeep.Notify(title, message, "")
}
