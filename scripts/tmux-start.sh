#!/bin/bash
# tmux-start.sh - Start all ScatterWeb components in a tmux session

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
CONFIG_DIR="$PROJECT_ROOT/configs"

SESSION_NAME="scatterweb"

# Create directories needed by the app
sudo mkdir -p /run/anonrouter /run/scatterweb
sudo mkdir -p /var/lib/anonrouter /var/lib/scatterweb
sudo chown "$USER:$USER" /run/anonrouter /run/scatterweb /var/lib/anonrouter /var/lib/scatterweb

# Kill existing session if running
tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true

# Create new session
tmux new-session -d -s "$SESSION_NAME" -x 240 -y 50

# Build the layout with empty panes first
# Split right: 0 left, 1 right
tmux split-window -t "$SESSION_NAME" -h

# Split pane 0 vertically: 0 top-left, 2 bottom-left (1 stays on right)
tmux split-window -t "$SESSION_NAME:0.0" -v

# Split pane 1 vertically: 1 top-right, 3 bottom-right (0, 2 stay on left)
tmux split-window -t "$SESSION_NAME:0.1" -v

# Split pane 2 vertically: 2 top, 4 bottom (on the left side)
tmux split-window -t "$SESSION_NAME:0.2" -v

# Now send commands to each pane
sleep 1
tmux send-keys -t "$SESSION_NAME:0.0" "$BUILD_DIR/anonrouter/sw-anonrouter $CONFIG_DIR/anonrouter.conf" Enter
tmux send-keys -t "$SESSION_NAME:0.1" "sleep 1 && $BUILD_DIR/inbox/sw-inbox $CONFIG_DIR/inbox.conf" Enter
tmux send-keys -t "$SESSION_NAME:0.2" "sleep 1 && $BUILD_DIR/outbox/sw-outbox $CONFIG_DIR/outbox.conf" Enter
tmux send-keys -t "$SESSION_NAME:0.3" "sleep 2 && $BUILD_DIR/client/sw-client $CONFIG_DIR/client.conf" Enter
tmux send-keys -t "$SESSION_NAME:0.4" "cd $PROJECT_ROOT && echo 'UI/CLI window ready. Run commands here.'" Enter

# Select main pane
tmux select-pane -t "$SESSION_NAME:0.0"

# Attach to the session
tmux attach-session -t "$SESSION_NAME"
