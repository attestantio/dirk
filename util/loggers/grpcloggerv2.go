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
	"fmt"

	"github.com/rs/zerolog"
)

// GRPCLoggerV2 provides the GRPC LoggerV2 interface with a zerolog backend.
type GRPCLoggerV2 struct {
	log zerolog.Logger
}

// NewGRPCLoggerV2 instantiates a GRPC LoggerV2 with a zerolog backend.
func NewGRPCLoggerV2(log zerolog.Logger) *GRPCLoggerV2 {
	return &GRPCLoggerV2{log: log}
}

// Info logs to INFO log. Arguments are handled in the manner of fmt.Print.
func (l *GRPCLoggerV2) Info(args ...interface{}) {
	l.log.Info().Msg(fmt.Sprint(args...))
}

// Infoln logs to INFO log. Arguments are handled in the manner of fmt.Println.
func (l *GRPCLoggerV2) Infoln(args ...interface{}) {
	l.Info(args...)
}

// Infof logs to INFO log. Arguments are handled in the manner of fmt.Printf.
func (l *GRPCLoggerV2) Infof(format string, args ...interface{}) {
	l.log.Info().Msgf(format, args...)
}

// Warning logs to WARNING log. Arguments are handled in the manner of fmt.Print.
func (l *GRPCLoggerV2) Warning(args ...interface{}) {
	l.log.Warn().Msg(fmt.Sprint(args...))
}

// Warningln logs to WARNING log. Arguments are handled in the manner of fmt.Println.
func (l *GRPCLoggerV2) Warningln(args ...interface{}) {
	l.Warning(args...)
}

// Warningf logs to WARNING log. Arguments are handled in the manner of fmt.Printf.
func (l *GRPCLoggerV2) Warningf(format string, args ...interface{}) {
	l.log.Warn().Msgf(format, args...)
}

// Error logs to ERROR log. Arguments are handled in the manner of fmt.Print.
func (l *GRPCLoggerV2) Error(args ...interface{}) {
	l.log.Error().Msg(fmt.Sprint(args...))
}

// Errorln logs to ERROR log. Arguments are handled in the manner of fmt.Println.
func (l *GRPCLoggerV2) Errorln(args ...interface{}) {
	l.Error(args...)
}

// Errorf logs to ERROR log. Arguments are handled in the manner of fmt.Printf.
func (l *GRPCLoggerV2) Errorf(format string, args ...interface{}) {
	l.log.Error().Msgf(format, args...)
}

// Fatal logs to ERROR log. Arguments are handled in the manner of fmt.Print.
// gRPC ensures that all Fatal logs will exit with os.Exit(1).
// Implementations may also call os.Exit() with a non-zero exit code.
func (l *GRPCLoggerV2) Fatal(args ...interface{}) {
	l.log.Fatal().Msg(fmt.Sprint(args...))
}

// Fatalln logs to ERROR log. Arguments are handled in the manner of fmt.Println.
// gRPC ensures that all Fatal logs will exit with os.Exit(1).
// Implementations may also call os.Exit() with a non-zero exit code.
func (l *GRPCLoggerV2) Fatalln(args ...interface{}) {
	l.Fatal(args...)
}

// Fatalf logs to ERROR log. Arguments are handled in the manner of fmt.Printf.
// gRPC ensures that all Fatal logs will exit with os.Exit(1).
// Implementations may also call os.Exit() with a non-zero exit code.
func (l *GRPCLoggerV2) Fatalf(format string, args ...interface{}) {
	l.log.Fatal().Msgf(format, args...)
}

// V reports whether verbosity level l is at least the requested verbose level.
func (l *GRPCLoggerV2) V(level int) bool {
	return int(l.log.GetLevel()) >= level
}
