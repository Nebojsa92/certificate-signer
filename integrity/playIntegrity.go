package integrity

import (
	"context"
	"encoding/json"

	log "github.com/sirupsen/logrus"

	"google.golang.org/api/option"
	playintegrity "google.golang.org/api/playintegrity/v1"
)

type PlayIntegrityManager struct {
	Service *playintegrity.Service
	env     string
}

func NewPlayIntegrityManager(serviceAccountJSONString string, env string) (*PlayIntegrityManager, error) {
	ctx := context.Background()

	// Create the Play Integrity API service
	service, err := playintegrity.NewService(ctx, option.WithCredentialsJSON([]byte(serviceAccountJSONString)))
	if err != nil {
		return nil, err
	}

	return &PlayIntegrityManager{
		Service: service,
		env:     env,
	}, nil
}

func (manager *PlayIntegrityManager) VerifyIntegrityToken(token string, hash string, packageName string) (bool, error) {
	ctx := context.Background()
	request := &playintegrity.DecodeIntegrityTokenRequest{
		IntegrityToken: token,
	}
	response, err := manager.Service.V1.DecodeIntegrityToken(packageName, request).Context(ctx).Do()
	if err != nil {
		return false, err
	}
	return manager.verdict(response.TokenPayloadExternal), nil
}

func (manager *PlayIntegrityManager) MarshalTokenPayload(response *playintegrity.TokenPayloadExternal) (string, error) {
	data, err := json.Marshal(response)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (manager *PlayIntegrityManager) verdict(payload *playintegrity.TokenPayloadExternal) bool {
	var result bool

	if manager.env == "development" {
		// emulator can never pass the integrity check
		result = true
	} else {
		result = manager.VerifyAccountDetails(payload) &&
			manager.VerifyDeviceIntegrity(payload) &&
			manager.VerifyAppIntegrity(payload)
	}
	if !result {
		data, _ := manager.MarshalTokenPayload(payload)
		log.Printf("Integrity verification failed: %s", data)
	}
	return result
}

func (manager *PlayIntegrityManager) VerifyAccountDetails(payload *playintegrity.TokenPayloadExternal) bool {
	//   "LICENSED" - The app and certificate match the versions distributed by Play.
	//   "UNLICENSED" - The certificate or package name does not match Google Play records.
	//   "UNKNOWN" - Play does not have sufficient information to evaluate licensing details
	//   "UNEVALUATED" - Licensing details were not evaluated since a necessary requirement was missed. For example DeviceIntegrity did not meet the minimum bar or the application was not a known Play version.
	return payload.AccountDetails != nil && payload.AccountDetails.AppLicensingVerdict == "LICENSED"
}

func (manager *PlayIntegrityManager) VerifyDeviceIntegrity(payload *playintegrity.TokenPayloadExternal) bool {
	// DeviceRecognitionVerdict: Details about the integrity of the device the app is running on.
	// "UNKNOWN" - Play does not have sufficient information to evaluate device integrity
	// "MEETS_BASIC_INTEGRITY" - App is running on a device that passes basic system integrity checks, but may not meet Android platform compatibility requirements and may not be approved to run Google Play services.
	// "MEETS_DEVICE_INTEGRITY" - App is running on GMS Android device with Google Play services.
	// "MEETS_STRONG_INTEGRITY" - App is running on GMS Android device with Google Play services and has a strong guarantee of system integrity such as a hardware-backed keystore.
	// "MEETS_VIRTUAL_INTEGRITY" - App is running on an Android emulator with Google Play services which meets core Android compatibility requirements.
	if payload.DeviceIntegrity == nil {
		return false
	}

	for _, verdict := range payload.DeviceIntegrity.DeviceRecognitionVerdict {
		if verdict == "MEETS_DEVICE_INTEGRITY" || verdict == "MEETS_STRONG_INTEGRITY" {
			return true
		}
	}
	return false
}

func (manager *PlayIntegrityManager) VerifyAppIntegrity(payload *playintegrity.TokenPayloadExternal) bool {
	// AppRecognitionVerdict: Required. Details about the app recognition verdict
	//   "UNKNOWN" - Play does not have sufficient information to evaluate app integrity
	//   "PLAY_RECOGNIZED" - The app and certificate match the versions distributed	by Play.
	//   "UNRECOGNIZED_VERSION" - The certificate or package name does not match Google Play records.
	//   "UNEVALUATED" - Application integrity was not evaluated since a necessary requirement was missed. For example DeviceIntegrity did not meet the minimum bar.
	return payload.AppIntegrity != nil && payload.AppIntegrity.AppRecognitionVerdict == "PLAY_RECOGNIZED"
}
