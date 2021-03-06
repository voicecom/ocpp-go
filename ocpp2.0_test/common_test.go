package ocpp2_test

import (
	"github.com/voicecom/ocpp-go/ocpp2.0/types"
	"time"
)

// Utility functions
func newInt(i int) *int {
	return &i
}

func newFloat(f float64) *float64 {
	return &f
}

// Test
func (suite *OcppV2TestSuite) TestIdTokenInfoValidation() {
	var testTable = []GenericTestEntry{
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: "l1", Language2: "l2", GroupIdToken: &types.GroupIdToken{IdToken: "1234", Type: types.IdTokenTypeCentral}, PersonalMessage: &types.MessageContent{Format: types.MessageFormatUTF8, Language: "en", Content: "random"}}, true},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: "l1", Language2: "l2", GroupIdToken: &types.GroupIdToken{IdToken: "1234", Type: types.IdTokenTypeCentral}, PersonalMessage: &types.MessageContent{Format: types.MessageFormatUTF8, Content: "random"}}, true},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: "l1", Language2: "l2", GroupIdToken: &types.GroupIdToken{IdToken: "1234", Type: types.IdTokenTypeCentral}}, true},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: "l1", Language2: "l2"}, true},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: "l1"}, true},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1}, true},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now())}, true},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted}, true},
		{types.IdTokenInfo{}, false},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: "l1", Language2: "l2", GroupIdToken: &types.GroupIdToken{IdToken: "1234", Type: types.IdTokenTypeCentral}, PersonalMessage: &types.MessageContent{Format: "invalidFormat", Language: "en", Content: "random"}}, false},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: "l1", Language2: "l2", GroupIdToken: &types.GroupIdToken{IdToken: "1234", Type: types.IdTokenTypeCentral}, PersonalMessage: &types.MessageContent{Format: types.MessageFormatUTF8, Language: "en", Content: ">512............................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................."}}, false},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: "l1", Language2: "l2", GroupIdToken: &types.GroupIdToken{IdToken: "1234", Type: types.IdTokenTypeCentral}, PersonalMessage: &types.MessageContent{Format: types.MessageFormatUTF8, Language: "en"}}, false},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: "l1", Language2: "l2", GroupIdToken: &types.GroupIdToken{IdToken: "1234", Type: types.IdTokenTypeCentral}, PersonalMessage: &types.MessageContent{}}, false},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: "l1", Language2: "l2", GroupIdToken: &types.GroupIdToken{IdToken: "1234", Type: "invalidTokenType"}}, false},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: "l1", Language2: "l2", GroupIdToken: &types.GroupIdToken{Type: types.IdTokenTypeCentral}}, false},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: "l1", Language2: "l2", GroupIdToken: &types.GroupIdToken{IdToken: "1234"}}, false},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: "l1", Language2: "l2", GroupIdToken: &types.GroupIdToken{}}, false},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: "l1", Language2: ">8......."}, false},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 1, Language1: ">8.......", Language2: "l2"}, false},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: -10}, false},
		{types.IdTokenInfo{Status: types.AuthorizationStatusAccepted, CacheExpiryDateTime: types.NewDateTime(time.Now()), ChargingPriority: 10}, false},
		{types.IdTokenInfo{Status: "invalidAuthStatus"}, false},
	}
	ExecuteGenericTestTable(suite.T(), testTable)
}

func (suite *OcppV2TestSuite) TestChargingSchedulePeriodValidation() {
	t := suite.T()
	var testTable = []GenericTestEntry{
		{types.ChargingSchedulePeriod{StartPeriod: 0, Limit: 10.0, NumberPhases: newInt(3)}, true},
		{types.ChargingSchedulePeriod{StartPeriod: 0, Limit: 10.0}, true},
		{types.ChargingSchedulePeriod{StartPeriod: 0}, true},
		{types.ChargingSchedulePeriod{}, true},
		{types.ChargingSchedulePeriod{StartPeriod: 0, Limit: -1.0}, false},
		{types.ChargingSchedulePeriod{StartPeriod: -1, Limit: 10.0}, false},
		{types.ChargingSchedulePeriod{StartPeriod: 0, Limit: 10.0, NumberPhases: newInt(-1)}, false},
	}
	ExecuteGenericTestTable(t, testTable)
}

func (suite *OcppV2TestSuite) TestChargingScheduleValidation() {
	t := suite.T()
	chargingSchedulePeriods := make([]types.ChargingSchedulePeriod, 2)
	chargingSchedulePeriods[0] = types.NewChargingSchedulePeriod(0, 10.0)
	chargingSchedulePeriods[1] = types.NewChargingSchedulePeriod(100, 8.0)
	var testTable = []GenericTestEntry{
		{types.ChargingSchedule{Duration: newInt(0), StartSchedule: types.NewDateTime(time.Now()), ChargingRateUnit: types.ChargingRateUnitWatts, ChargingSchedulePeriod: chargingSchedulePeriods, MinChargingRate: newFloat(1.0)}, true},
		{types.ChargingSchedule{Duration: newInt(0), ChargingRateUnit: types.ChargingRateUnitWatts, ChargingSchedulePeriod: chargingSchedulePeriods, MinChargingRate: newFloat(1.0)}, true},
		{types.ChargingSchedule{Duration: newInt(0), ChargingRateUnit: types.ChargingRateUnitWatts, ChargingSchedulePeriod: chargingSchedulePeriods}, true},
		{types.ChargingSchedule{Duration: newInt(0), ChargingRateUnit: types.ChargingRateUnitWatts}, false},
		{types.ChargingSchedule{Duration: newInt(0), ChargingSchedulePeriod: chargingSchedulePeriods}, false},
		{types.ChargingSchedule{Duration: newInt(-1), StartSchedule: types.NewDateTime(time.Now()), ChargingRateUnit: types.ChargingRateUnitWatts, ChargingSchedulePeriod: chargingSchedulePeriods, MinChargingRate: newFloat(1.0)}, false},
		{types.ChargingSchedule{Duration: newInt(0), StartSchedule: types.NewDateTime(time.Now()), ChargingRateUnit: types.ChargingRateUnitWatts, ChargingSchedulePeriod: chargingSchedulePeriods, MinChargingRate: newFloat(-1.0)}, false},
		{types.ChargingSchedule{Duration: newInt(0), StartSchedule: types.NewDateTime(time.Now()), ChargingRateUnit: types.ChargingRateUnitWatts, ChargingSchedulePeriod: make([]types.ChargingSchedulePeriod, 0), MinChargingRate: newFloat(1.0)}, false},
		{types.ChargingSchedule{Duration: newInt(-1), StartSchedule: types.NewDateTime(time.Now()), ChargingRateUnit: "invalidChargeRateUnit", ChargingSchedulePeriod: chargingSchedulePeriods, MinChargingRate: newFloat(1.0)}, false},
	}
	ExecuteGenericTestTable(t, testTable)
}

func (suite *OcppV2TestSuite) TestComponentVariableValidation() {
	t := suite.T()
	var testTable = []GenericTestEntry{
		{types.ComponentVariable{Component: types.Component{Name: "component1", Instance: "instance1", EVSE: &types.EVSE{ID: 2, ConnectorID: newInt(2)}}, Variable: types.Variable{Name: "variable1", Instance: "instance1"}}, true},
		{types.ComponentVariable{Component: types.Component{Name: "component1", Instance: "instance1", EVSE: &types.EVSE{ID: 2}}, Variable: types.Variable{Name: "variable1", Instance: "instance1"}}, true},
		{types.ComponentVariable{Component: types.Component{Name: "component1", EVSE: &types.EVSE{ID: 2}}, Variable: types.Variable{Name: "variable1", Instance: "instance1"}}, true},
		{types.ComponentVariable{Component: types.Component{Name: "component1", EVSE: &types.EVSE{ID: 2}}, Variable: types.Variable{Name: "variable1"}}, true},
		{types.ComponentVariable{Component: types.Component{Name: "component1", EVSE: &types.EVSE{}}, Variable: types.Variable{Name: "variable1"}}, true},
		{types.ComponentVariable{Component: types.Component{Name: "component1"}, Variable: types.Variable{Name: "variable1"}}, true},
		{types.ComponentVariable{Component: types.Component{Name: "component1"}, Variable: types.Variable{}}, false},
		{types.ComponentVariable{Component: types.Component{}, Variable: types.Variable{Name: "variable1"}}, false},
		{types.ComponentVariable{Variable: types.Variable{Name: "variable1"}}, false},
		{types.ComponentVariable{Component: types.Component{Name: "component1"}}, false},
		{types.ComponentVariable{Component: types.Component{Name: ">50................................................", Instance: "instance1", EVSE: &types.EVSE{ID: 2, ConnectorID: newInt(2)}}, Variable: types.Variable{Name: "variable1", Instance: "instance1"}}, false},
		{types.ComponentVariable{Component: types.Component{Name: "component1", Instance: ">50................................................", EVSE: &types.EVSE{ID: 2, ConnectorID: newInt(2)}}, Variable: types.Variable{Name: "variable1", Instance: "instance1"}}, false},
		{types.ComponentVariable{Component: types.Component{Name: "component1", Instance: "instance1", EVSE: &types.EVSE{ID: 2, ConnectorID: newInt(2)}}, Variable: types.Variable{Name: ">50................................................", Instance: "instance1"}}, false},
		{types.ComponentVariable{Component: types.Component{Name: "component1", Instance: "instance1", EVSE: &types.EVSE{ID: 2, ConnectorID: newInt(2)}}, Variable: types.Variable{Name: "variable1", Instance: ">50................................................"}}, false},
		{types.ComponentVariable{Component: types.Component{Name: "component1", Instance: "instance1", EVSE: &types.EVSE{ID: 2, ConnectorID: newInt(-2)}}, Variable: types.Variable{Name: "variable1", Instance: "instance1"}}, false},
		{types.ComponentVariable{Component: types.Component{Name: "component1", Instance: "instance1", EVSE: &types.EVSE{ID: -2, ConnectorID: newInt(2)}}, Variable: types.Variable{Name: "variable1", Instance: "instance1"}}, false},
	}
	ExecuteGenericTestTable(t, testTable)
}

func (suite *OcppV2TestSuite) TestChargingProfileValidation() {
	t := suite.T()
	chargingSchedule := types.NewChargingSchedule(types.ChargingRateUnitWatts, types.NewChargingSchedulePeriod(0, 10.0), types.NewChargingSchedulePeriod(100, 8.0))
	var testTable = []GenericTestEntry{
		{types.ChargingProfile{ChargingProfileId: 1, TransactionId: 1, StackLevel: 1, ChargingProfilePurpose: types.ChargingProfilePurposeChargingStationMaxProfile, ChargingProfileKind: types.ChargingProfileKindAbsolute, RecurrencyKind: types.RecurrencyKindDaily, ValidFrom: types.NewDateTime(time.Now()), ValidTo: types.NewDateTime(time.Now().Add(8 * time.Hour)), ChargingSchedule: chargingSchedule}, true},
		{types.ChargingProfile{ChargingProfileId: 1, StackLevel: 1, ChargingProfilePurpose: types.ChargingProfilePurposeChargingStationMaxProfile, ChargingProfileKind: types.ChargingProfileKindAbsolute, ChargingSchedule: chargingSchedule}, true},
		{types.ChargingProfile{ChargingProfileId: 1, StackLevel: 1, ChargingProfilePurpose: types.ChargingProfilePurposeChargingStationMaxProfile, ChargingProfileKind: types.ChargingProfileKindAbsolute}, false},
		{types.ChargingProfile{ChargingProfileId: 1, StackLevel: 1, ChargingProfilePurpose: types.ChargingProfilePurposeChargingStationMaxProfile, ChargingSchedule: chargingSchedule}, false},
		{types.ChargingProfile{ChargingProfileId: 1, StackLevel: 1, ChargingProfileKind: types.ChargingProfileKindAbsolute, ChargingSchedule: chargingSchedule}, false},
		{types.ChargingProfile{ChargingProfileId: 1, ChargingProfilePurpose: types.ChargingProfilePurposeChargingStationMaxProfile, ChargingProfileKind: types.ChargingProfileKindAbsolute, ChargingSchedule: chargingSchedule}, false},
		{types.ChargingProfile{StackLevel: 1, ChargingProfilePurpose: types.ChargingProfilePurposeChargingStationMaxProfile, ChargingProfileKind: types.ChargingProfileKindAbsolute, ChargingSchedule: chargingSchedule}, true},
		{types.ChargingProfile{ChargingProfileId: 1, StackLevel: 1, ChargingProfilePurpose: types.ChargingProfilePurposeChargingStationMaxProfile, ChargingProfileKind: "invalidChargingProfileKind", ChargingSchedule: chargingSchedule}, false},
		{types.ChargingProfile{ChargingProfileId: 1, StackLevel: 1, ChargingProfilePurpose: "invalidChargingProfilePurpose", ChargingProfileKind: types.ChargingProfileKindAbsolute, ChargingSchedule: chargingSchedule}, false},
		{types.ChargingProfile{ChargingProfileId: 1, StackLevel: 0, ChargingProfilePurpose: types.ChargingProfilePurposeChargingStationMaxProfile, ChargingProfileKind: types.ChargingProfileKindAbsolute, ChargingSchedule: chargingSchedule}, false},
		{types.ChargingProfile{ChargingProfileId: 1, StackLevel: 1, ChargingProfilePurpose: types.ChargingProfilePurposeChargingStationMaxProfile, ChargingProfileKind: types.ChargingProfileKindAbsolute, RecurrencyKind: "invalidRecurrencyKind", ChargingSchedule: chargingSchedule}, false},
		{types.ChargingProfile{ChargingProfileId: 1, StackLevel: 1, ChargingProfilePurpose: types.ChargingProfilePurposeChargingStationMaxProfile, ChargingProfileKind: types.ChargingProfileKindAbsolute, ChargingSchedule: types.NewChargingSchedule(types.ChargingRateUnitWatts)}, false},
	}
	ExecuteGenericTestTable(t, testTable)
}

func (suite *OcppV2TestSuite) TestSampledValueValidation() {
	t := suite.T()
	var testTable = []GenericTestEntry{
		{types.SampledValue{Value: "value", Context: types.ReadingContextTransactionEnd, Format: types.ValueFormatRaw, Measurand: types.MeasurandPowerActiveExport, Phase: types.PhaseL2, Location: types.LocationBody, Unit: types.UnitOfMeasureKW}, true},
		{types.SampledValue{Value: "value", Context: types.ReadingContextTransactionEnd, Format: types.ValueFormatRaw, Measurand: types.MeasurandPowerActiveExport, Phase: types.PhaseL2, Location: types.LocationBody}, true},
		{types.SampledValue{Value: "value", Context: types.ReadingContextTransactionEnd, Format: types.ValueFormatRaw, Measurand: types.MeasurandPowerActiveExport, Phase: types.PhaseL2}, true},
		{types.SampledValue{Value: "value", Context: types.ReadingContextTransactionEnd, Format: types.ValueFormatRaw, Measurand: types.MeasurandPowerActiveExport}, true},
		{types.SampledValue{Value: "value", Context: types.ReadingContextTransactionEnd, Format: types.ValueFormatRaw}, true},
		{types.SampledValue{Value: "value", Context: types.ReadingContextTransactionEnd}, true},
		{types.SampledValue{Value: "value"}, true},
		{types.SampledValue{Value: "value", Context: "invalidContext"}, false},
		{types.SampledValue{Value: "value", Format: "invalidFormat"}, false},
		{types.SampledValue{Value: "value", Measurand: "invalidMeasurand"}, false},
		{types.SampledValue{Value: "value", Phase: "invalidPhase"}, false},
		{types.SampledValue{Value: "value", Location: "invalidLocation"}, false},
		{types.SampledValue{Value: "value", Unit: "invalidUnit"}, false},
	}
	ExecuteGenericTestTable(t, testTable)
}

func (suite *OcppV2TestSuite) TestMeterValueValidation() {
	var testTable = []GenericTestEntry{
		{types.MeterValue{Timestamp: types.NewDateTime(time.Now()), SampledValue: []types.SampledValue{{Value: "value"}, {Value: "value2", Unit: types.UnitOfMeasureKW}}}, true},
		{types.MeterValue{Timestamp: types.NewDateTime(time.Now()), SampledValue: []types.SampledValue{{Value: "value"}}}, true},
		{types.MeterValue{Timestamp: types.NewDateTime(time.Now()), SampledValue: []types.SampledValue{}}, false},
		{types.MeterValue{Timestamp: types.NewDateTime(time.Now())}, false},
		{types.MeterValue{SampledValue: []types.SampledValue{{Value: "value"}}}, false},
	}
	ExecuteGenericTestTable(suite.T(), testTable)
}
