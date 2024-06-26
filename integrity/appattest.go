package integrity

import (
	"encoding/json"
	"errors"

	attest "github.com/bas-d/appattest/attestation"
)

type AppAttestManager struct {
	isProduction           bool
	appleDevelopmentTeamID string
}

type AttestData struct {
	KeyID             string `json:"keyID" schema:"keyID"`
	AttestationObject []byte `json:"attestationObject" schema:"attestationObject"`
	ClientData        []byte `json:"clientData" schema:"clientData"`
}

func NewAppAttestManager(env string, appleDevelopmentTeamID string) (*AppAttestManager, error) {
	if (env != "production") && (env != "development") {
		return nil, errors.New("invalid environment. Must be either 'production' or 'development'")
	}
	return &AppAttestManager{
		isProduction:           env == "production",
		appleDevelopmentTeamID: appleDevelopmentTeamID,
	}, nil
}

func (manager *AppAttestManager) VerifyAttestationToken(jsonRawData []byte, appID string) (bool, error) {
	if !manager.isProduction {
		return true, nil
	}

	var jsonData AttestData
	err := json.Unmarshal(jsonRawData, &jsonData)
	if err != nil {
		return false, err
	}

	aar := attest.AuthenticatorAttestationResponse{
		KeyID:             jsonData.KeyID,
		AttestationObject: jsonData.AttestationObject,
		ClientData:        jsonData.ClientData,
	}

	_, _, err = aar.Verify(manager.appleDevelopmentTeamID+"."+appID, manager.isProduction)
	if err != nil {
		return false, err
	}
	return true, nil

}
