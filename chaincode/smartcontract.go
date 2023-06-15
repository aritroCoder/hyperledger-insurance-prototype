package chaincode

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// insurance policy smart contract. It consists of a insuring organization
// and a client organization. The client organization can request for a policy
// and the insuring organization can approve or reject the request. The client
// organization can also claim for the policy and the insuring organization can
// approve or reject the claim.

type SmartContract struct {
	contractapi.Contract
}

type ClaimStatus int

const (
	NotClaimed ClaimStatus = iota
	Claimed
)

type InsuredItemStatus int

const (
	New InsuredItemStatus = iota
	Old
	NotWorking
)

type ClaimApproved int

const (
	Approved ClaimApproved = iota
	Rejected
	NA
)

type Date struct {
	Day   int `json:"day"`
	Month int `json:"month"`
	Year  int `json:"year"`
}

// Policy struct
type Policy struct {
	ID                     string            `json:"id"`
	InsuredItem            string            `json:"insuredItem"`
	InsuredItemValue       int               `json:"insuredItemValue"`
	InsuredItemStatus      InsuredItemStatus `json:"insuredItemStatus"`
	InsurancePremiumAmount int               `json:"insurancePremiumAmount"`
	ClaimStatus            ClaimStatus       `json:"claimStatus"`
	InsuredTo              string            `json:"insuredTo"`
	InsuredAt              Date              `json:"insuredAt"`
	NumberOfPremiumsPaid   int               `json:"numberOfPremiumsPaid"`
	ClaimApproved          ClaimApproved     `json:"claimApproved"`
}

// CreatePolicy creates a new policy on a new item on the ledger
func (s *SmartContract) CreatePolicy(ctx contractapi.TransactionContextInterface, id string, insuredItem string, insuredItemValue int, premium int, initialPremiumAmount int) error {
	// check if policy already exists
	exists, err := s.PolicyExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the policy %s already exists", id)
	}

	if premium != initialPremiumAmount {
		return fmt.Errorf("the premium amount is not correct")
	}

	var date Date = Date{
		Day:   time.Now().Day(),
		Month: int(time.Now().Month()),
		Year:  time.Now().Year(),
	}
	// get the creator of the transaction
	creatorOrg, _, err := getTxCreatorInfo(ctx)
	if err != nil {
		return err
	}

	var statusOfClaim ClaimStatus = NotClaimed
	var insuredItemValueStatus InsuredItemStatus = New

	policy := Policy{
		ID:                     id,
		InsuredItem:            insuredItem,
		InsuredItemValue:       insuredItemValue,
		InsuredItemStatus:      insuredItemValueStatus,
		InsurancePremiumAmount: premium,
		ClaimStatus:            statusOfClaim,
		InsuredTo:              creatorOrg,
		InsuredAt:              date,
		NumberOfPremiumsPaid:   1,
		ClaimApproved:          NA,
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(policy.ID, policyJSON)
}

// ReadPolicy returns the policy stored in the world state with given id
func (s *SmartContract) ReadPolicy(ctx contractapi.TransactionContextInterface, id string) (*Policy, error) {
	policyJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if policyJSON == nil {
		return nil, fmt.Errorf("the policy %s does not exist", id)
	}

	var policy Policy
	err = json.Unmarshal(policyJSON, &policy)
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

// GetAllPolicies lists all existing policy details
func (s *SmartContract) GetAllPolicies(ctx contractapi.TransactionContextInterface) ([]*Policy, error) {
	// range query with empty string for startKey and endKey does an
	// open-ended query of all assets in the chaincode namespace.
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var policies []*Policy
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var policy Policy
		err = json.Unmarshal(queryResponse.Value, &policy)
		if err != nil {
			return nil, err
		}
		policies = append(policies, &policy)
	}
	return policies, nil
}

// PayPremium pays the premium for the policy at each month
func (s *SmartContract) PayPremium(ctx contractapi.TransactionContextInterface, amount int, id string) error {
	policy, err := s.ReadPolicy(ctx, id)
	if err != nil {
		return err
	}

	if policy.InsurancePremiumAmount != amount {
		return fmt.Errorf("the premium amount is not correct")
	}

	policy.NumberOfPremiumsPaid += 1

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(policy.ID, policyJSON)
}

// ClaimPolicy claims the policy
func (s *SmartContract) ClaimPolicy(ctx contractapi.TransactionContextInterface, id string) error {
	policy, err := s.ReadPolicy(ctx, id)
	if err != nil {
		return err
	}
	var currentDate Date = Date{Day: time.Now().Day(), Month: int(time.Now().Month()), Year: time.Now().Year()}
	var requiredPremiums = DateDiff(currentDate, policy.InsuredAt) + 1 // considering origin month
	if policy.NumberOfPremiumsPaid < requiredPremiums {
		return fmt.Errorf("you did not pay all the premiums of policy: %s", id)
	}

	if policy.InsuredItemStatus != NotWorking {
		return fmt.Errorf("you can only claim insurance if item is not working")
	}

	if policy.ClaimStatus == Claimed {
		return fmt.Errorf("you have already claimed the policy: %s", id)
	}
	// update policy to be claimed
	policy.ClaimStatus = Claimed
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %v", err)
	}

	return ctx.GetStub().PutState(policy.ID, policyJSON)
}

// ApprovePolicy approves the claim and transfers amount to client
func (s *SmartContract) ApprovePolicy(ctx contractapi.TransactionContextInterface, id string) error {
	//TODO: implement logic that prevents anyone except the insuring organization to approve the claim
	policy, err := s.ReadPolicy(ctx, id)
	if err != nil {
		return err
	}
	if policy.ClaimStatus != Claimed {
		return fmt.Errorf("you can only approve a claimed policy")
	}
	if policy.ClaimApproved == Approved {
		return fmt.Errorf("you have already approved the claim")
	}
	//TODO: implement business logic check before approval

	// update policy to be approved
	policy.ClaimApproved = Approved
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %v", err)
	}
	return ctx.GetStub().PutState(policy.ID, policyJSON)
}

// UpdatePolicy updates the policy
func (s *SmartContract) UpdateInsuredItemStatus(ctx contractapi.TransactionContextInterface, id string, status InsuredItemStatus) error {
	policy, err := s.ReadPolicy(ctx, id)
	if err != nil {
		return err
	}
	policy.InsuredItemStatus = status
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %v", err)
	}
	return ctx.GetStub().PutState(policy.ID, policyJSON)
}

// ----------------------------helper functions--------------------------------
// DateDiff returns the difference between two dates in months
func DateDiff(date1 Date, date2 Date) int {
	var diff int
	diff = (date1.Year - date2.Year) * 12
	diff += date1.Month - date2.Month
	return diff
}

// PolicyExists returns true when policy with given ID exists in world state
func (s *SmartContract) PolicyExists(ctx contractapi.TransactionContextInterface, policyID string) (bool, error) {
	policyJSON, err := ctx.GetStub().GetState(policyID)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}
	return policyJSON != nil, nil
}

// Get Tx Creator Info
func getTxCreatorInfo(ctx contractapi.TransactionContextInterface) (string, string, error) {
	var mspid string
	var err error
	var cert *x509.Certificate
	mspid, err = cid.GetMSPID(ctx.GetStub())

	if err != nil {
		fmt.Printf("Error getting MSP identity: %sn", err.Error())
		return "", "", err
	}

	cert, err = cid.GetX509Certificate(ctx.GetStub())
	if err != nil {
		fmt.Printf("Error getting client certificate: %sn", err.Error())
		return "", "", err
	}
	// creatorOrg, creatorCertIssuer, error := getTxCreatorInfo(ctx)
	return mspid, cert.Issuer.CommonName, nil
}
