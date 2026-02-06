yarn pbjs -t static-module -w es6 -o ./src/WhisperTextProtocol.js ./protos/WhisperTextProtocol.proto
# Fix protobufjs import for ESM:
# 1. Node.js requires .js extension for subpath imports
# 2. protobufjs uses CJS, so we need default import instead of namespace import
sed -i 's|import \* as \$protobuf from "protobufjs/minimal"|import \$protobuf from "protobufjs/minimal.js"|' ./src/WhisperTextProtocol.js
