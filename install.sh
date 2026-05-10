#!/usr/bin/env bash
set -euo pipefail

# AI Security Audit Skills — 一键安装
# 支持 Claude Code 和 Hermes Agent 两大平台

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_SKILLS_DIR="${HOME}/.claude/skills"
HERMES_SKILLS_DIR="${HERMES_HOME:-${HOME}/.hermes}/skills"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  AI Security Audit Skills Installer  ${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# ── Claude Code Skills ──────────────────────────────────────
install_claude_skills() {
    echo -e "${YELLOW}[1/2] Installing Claude Code Skills...${NC}"
    mkdir -p "$CLAUDE_SKILLS_DIR"

    for skill_dir in "$SCRIPT_DIR"/claude-code-skills/*/; do
        skill_name=$(basename "$skill_dir")
        target="$CLAUDE_SKILLS_DIR/$skill_name"

        if [ -d "$target" ]; then
            echo "  ↻ Updating: $skill_name"
            rm -rf "$target"
        else
            echo "  + Installing: $skill_name"
        fi
        cp -r "$skill_dir" "$target"
    done
    echo -e "${GREEN}  ✓ Claude Code skills installed to $CLAUDE_SKILLS_DIR${NC}"
}

# ── Hermes Agent Skills ─────────────────────────────────────
install_hermes_skills() {
    echo -e "${YELLOW}[2/2] Installing Hermes Agent Skills...${NC}"

    if [ ! -d "$HERMES_SKILLS_DIR" ]; then
        echo -e "  ${YELLOW}⚠ Hermes skills directory not found: $HERMES_SKILLS_DIR${NC}"
        echo "  Hermes Agent may not be installed. Creating directory anyway..."
        mkdir -p "$HERMES_SKILLS_DIR"
    fi

    # Copy each category, preserving directory structure
    for category_dir in "$SCRIPT_DIR"/hermes-skills/*/; do
        category=$(basename "$category_dir")
        for skill_dir in "$category_dir"*/; do
            skill_name=$(basename "$skill_dir")
            target="$HERMES_SKILLS_DIR/$category/$skill_name"

            if [ -d "$target" ]; then
                echo "  ↻ Updating: $category/$skill_name"
                rm -rf "$target"
            else
                echo "  + Installing: $category/$skill_name"
                mkdir -p "$(dirname "$target")"
            fi
            cp -r "$skill_dir" "$target"
        done
    done
    echo -e "${GREEN}  ✓ Hermes skills installed to $HERMES_SKILLS_DIR${NC}"
}

# ── Main ────────────────────────────────────────────────────
install_claude_skills
echo ""
install_hermes_skills

echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}  Installation Complete!               ${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""
echo "Usage:"
echo "  Claude Code:  在对话中说 '审计这个代码' 或 '安全扫描' 即可触发"
echo "  Hermes Agent: hermes 会自动索引 skills/ 目录下的技能"
echo ""
echo "Optional tools for better scanning:"
echo "  pip install semgrep bandit pygount"
echo "  brew install gitleaks"
echo ""
