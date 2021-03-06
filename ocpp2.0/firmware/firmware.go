// The firmware functional block contains OCPP 2.0 features that enable firmware updates on a charging station.
package firmware

import "github.com/voicecom/ocpp-go/ocpp"

// Needs to be implemented by a CSMS for handling messages part of the OCPP 2.0 Firmware profile.
type CSMSHandler interface {
	// OnFirmwareStatusNotification is called on the CSMS whenever a FirmwareStatusNotificationRequest is received from a charging station.
	OnFirmwareStatusNotification(chargingStationID string, request *FirmwareStatusNotificationRequest) (confirmation *FirmwareStatusNotificationResponse, err error)
}

// Needs to be implemented by Charging stations for handling messages part of the OCPP 2.0 Firmware profile.
type ChargingStationHandler interface {
}

const ProfileName = "firmware"

var Profile = ocpp.NewProfile(
	ProfileName,
	FirmwareStatusNotificationFeature{},
)
