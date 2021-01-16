// Copyright © 2020 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package locker

// Service provides the features and functions for a global account locker.
type Service interface {
	// PreLock must be called prior to locking one or more public keys.
	// It obtains a locker-wide mutex, to ensure that only one goroutine
	// can be locking or unlocking groups of public keys at a time.
	PreLock()
	// PostLock must be called after locking one or more public keys.
	// It frees the locker-wide mutex obtained by PreLock().
	PostLock()
	// Lock acquires a lock for a given public key.
	// If more than one lock is being acquired in a batch, ensure that
	// PreLock() is called beforehand and PostLock() afterwards.
	Lock(key [48]byte)
	// Unlock frees a lock for a given public key.
	Unlock(key [48]byte)
}
