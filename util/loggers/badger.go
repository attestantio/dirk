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

package loggers

import (
	"strings"

	"github.com/rs/zerolog"
)

// BadgerLogger provides the Badger Logger interface with a zerolog backend.
type BadgerLogger struct {
	log zerolog.Logger
}

// NewBadgerLogger instantiates a Badger Logger with a zerolog backend.
func NewBadgerLogger(log zerolog.Logger) *BadgerLogger {
	// Badger logs more verbosely than Dirk, so turn down the verbosity a notch.
	switch log.GetLevel() {
	case zerolog.ErrorLevel, zerolog.FatalLevel, zerolog.PanicLevel:
		log = log.Level(zerolog.FatalLevel)
	case zerolog.WarnLevel:
		log = log.Level(zerolog.ErrorLevel)
	case zerolog.InfoLevel:
		log = log.Level(zerolog.WarnLevel)
	case zerolog.DebugLevel:
		log = log.Level(zerolog.InfoLevel)
	case zerolog.TraceLevel:
		log = log.Level(zerolog.TraceLevel)
	case zerolog.NoLevel, zerolog.Disabled:
	}
	log = log.With().Str("store", "badger").Logger()
	return &BadgerLogger{log: log}
}

// Errorf logs to ERROR log. Arguments are handled in the manner of fmt.Printf.
func (l *BadgerLogger) Errorf(format string, args ...interface{}) {
	l.log.Error().Msgf(strings.TrimSpace(format), args...)
}

// Warningf logs to WARNING log. Arguments are handled in the manner of fmt.Printf.
func (l *BadgerLogger) Warningf(format string, args ...interface{}) {
	l.log.Warn().Msgf(strings.TrimSpace(format), args...)
}

// Infof logs to INFO log. Arguments are handled in the manner of fmt.Printf.
func (l *BadgerLogger) Infof(format string, args ...interface{}) {
	l.log.Info().Msgf(strings.TrimSpace(format), args...)
}

// Debugf logs to DEBUG log. Arguments are handled in the manner of fmt.Printf.
func (l *BadgerLogger) Debugf(format string, args ...interface{}) {
	l.log.Debug().Msgf(strings.TrimSpace(format), args...)
}
