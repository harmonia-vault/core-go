package syncclient

import "github.com/harmonia-vault/core-go/localkeys"

// VaultDAGJournal 保留原 public 名称与固定槽行为，严格逻辑与 mobile 共用。
type VaultDAGJournal = CheckedDAGJournal

type vaultDAGStore struct{ vault *localkeys.Vault }

func (s vaultDAGStore) LoadDAGJournal(b DAGJournalBinding) ([]byte, error) {
	return s.vault.LoadRecoveryDAGJournal(b.AccountID, b.AccountGeneration, b.OwnerEpoch)
}
func (s vaultDAGStore) CompareAndSwapDAGJournal(b DAGJournalBinding, old, next []byte) error {
	return s.vault.CompareAndSwapRecoveryDAGJournal(b.AccountID, b.AccountGeneration, b.OwnerEpoch, old, next)
}
func NewVaultDAGJournal(vault *localkeys.Vault, endpoint, account string, generation uint64) (*VaultDAGJournal, error) {
	if vault == nil {
		return nil, localkeys.ErrClosed
	}
	epoch, err := vault.RecoveryDAGOwnerEpoch(account, generation)
	if err != nil {
		return nil, err
	}
	return NewCheckedDAGJournal(vaultDAGStore{vault}, DAGJournalBinding{Endpoint: endpoint, AccountID: account, AccountGeneration: generation, OwnerEpoch: epoch})
}
