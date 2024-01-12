#!/bin/bash

if [ "$(id -u)" != "0" ]; then
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
    else
        echo -e "${red}This script must be run as root or with sudo privileges.${no_color}"
        exit 1
    fi
else
    SUDO=""
fi

echo "初始化服务器配置..."

# 启动 ssh-agent
eval "$(ssh-agent -s)"

# 定义颜色代码
blue="\033[0;34m"
green="\033[0;32m"
yellow="\033[1;33m"
red="\033[0;31m"
no_color="\033[0m"

# 函数：初始化 SSH
function init_ssh() {
    local ssh_dir="$HOME/.ssh"
    local public_key_file="$ssh_dir/id_ed25519.pub"
    local authorized_keys_file="$ssh_dir/authorized_keys"
    local red="\033[0;31m"
    local no_color="\033[0m"

    # 确保 .ssh 目录存在
    if [ ! -d "$ssh_dir" ]; then
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"
    fi

    echo ""
    # 检查并询问用户是否生成新的 SSH 密钥
    if [ -f "$public_key_file" ]; then
        echo -e "${red}检测到已存在 SSH 密钥。生成新密钥将覆盖现有密钥。${no_color}"
        read -r -p "是否继续生成新密钥？(y/n): " confirm
        if [[ $confirm != "y" ]]; then
            echo "取消生成新密钥。"
            return 1
        fi
    fi

    echo ""
    # 询问用户是否添加注释
    read -r -p "是否添加注释到 SSH 密钥？(y/n): " add_comment
    local key_comment=""
    if [[ $add_comment == "y" ]]; then
        read -r -p "请输入密钥注释（通常为邮箱地址）: " key_comment
    fi

    echo ""
    # 生成 SSH 密钥
    if ! ssh-keygen -t ed25519 -C "$key_comment" ; then
        echo -e "${red}SSH 密钥生成失败。${no_color}"
        return 1
    fi

    echo ""
    # 检查公钥是否在 authorized_keys 中
    if [ -f "$authorized_keys_file" ] && ! grep -qFf "$public_key_file" "$authorized_keys_file"; then
        echo -e "${red}当前公钥不在 ~/.ssh/authorized_keys 文件中。请考虑手动添加。${no_color}"
    fi

    echo ""
    # 提示用户是否将公钥添加到本地的 ~/.ssh/authorized_keys
    read -r -p "是否将公钥添加到本地用户的 ~/.ssh/authorized_keys 文件中？(y/n): " append_to_auth_keys
    if [[ $append_to_auth_keys == "y" ]]; then
        cat "$public_key_file" >> "$authorized_keys_file"
        echo "公钥已添加到 ~/.ssh/authorized_keys 文件中。"
    fi

    echo ""
    # 改变目录和文件的权限
    chmod 700 "$ssh_dir"
    chmod 600 "$ssh_dir"/*

    echo -e "\n${blue}初始化 SSH 已成功执行${no_color}"
}


# 函数：添加新用户
function add_user() {
    read -r -p "是否添加新用户? (y/n): " add_new_user
    if [[ $add_new_user == "y" ]]; then
        read -r -p "输入新用户名: " new_username
        ${SUDO} adduser "$new_username"
        read -r -p "是否赋予新用户 sudo 权限? (y/n): " grant_sudo
        if [[ $grant_sudo == "y" ]]; then
            ${SUDO} usermod -aG sudo "$new_username"
        fi
    fi
    echo -e "${blue}添加新用户 已成功执行${no_color}"
}

# 函数：显示系统内的所有用户并提供删除选项
function show_and_delete_user() {
    echo -e "${green}系统内的所有用户:${no_color}"
    local users
    # 仅列出具有有效登录 shell 的用户
    mapfile -t users < <(awk -F: '{ if ($7 ~ /^(\/bin\/bash|\/bin\/sh)$/) print $1 }' /etc/passwd)
    local choice
    for i in "${!users[@]}"; do
        echo "$((i+1)). ${users[i]}"
    done
    while true; do
        echo -ne "${yellow}选择要删除的用户编号 (或输入 'q' 退出): ${no_color}"
        read -r choice
        echo
        if [[ $choice =~ ^[0-9]+$ ]] && [ "$choice" -le "${#users[@]}" ]; then
            ${SUDO} deluser "${users[$((choice-1))]}"
            echo "已删除用户: ${users[$((choice-1))]}"
        elif [[ $choice == 'q' ]]; then
            break
        else
            echo -e "${red}无效输入，请重试。${no_color}"
        fi
    done
    echo -e "${blue}显示和删除用户 已成功执行${no_color}"
}


# 函数：检查 SSH 配置并进行修改
function check_ssh_config() {
    # Display current status of PermitRootLogin
    if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
        current_permit_root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}')
    else
        current_permit_root_login="默认 (prohibit-password)"
    fi
    echo
    if [ "$current_permit_root_login" == "yes" ]; then
        echo -e "${red}当前 PermitRootLogin 配置: ${current_permit_root_login}${no_color}"
        echo
    else
        echo -e "${green}当前 PermitRootLogin 配置: ${current_permit_root_login}${no_color}"
    fi
    # Provide options to modify PermitRootLogin
    echo -e "${yellow}选择 PermitRootLogin 的配置: ${no_color}"
    echo -e "${red}1. 允许 root 登录 (PermitRootLogin yes)${no_color}"
    echo -e "${green}2. 禁止 root 登录 (PermitRootLogin no)${no_color}"
    echo -e "${green}3. 禁止 root 使用密码登录 (默认，通过注释实现)${no_color}"
    read -r -p "输入选项 (1/2/3/其他不修改): " permit_root_login_choice

    case $permit_root_login_choice in
        1)
            sudo sed -i '/^#*PermitRootLogin/c\PermitRootLogin yes' /etc/ssh/sshd_config
            echo -e "PermitRootLogin 设置为 ${red}yes${no_color}"
            ;;
        2)
            sudo sed -i '/^#*PermitRootLogin/c\PermitRootLogin no' /etc/ssh/sshd_config
            echo -e "PermitRootLogin 设置为 ${green}no${no_color}"
            ;;
        3)
            sudo sed -i '/^#*PermitRootLogin/c\#PermitRootLogin prohibit-password' /etc/ssh/sshd_config
            echo -e "PermitRootLogin 设置为 ${green}prohibit-password${no_color}"
            ;;
        *)
            # No changes
            echo -e "${blue}PermitRootLogin 未改变${no_color}"
            ;;
    esac

    # Check and modify PasswordAuthentication
    current_password_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config | awk '{print $2}')
    echo
    if [ "$current_password_auth" == "yes" ]; then
        echo -e "${red}当前 PasswordAuthentication 配置: ${current_password_auth}${no_color}"
    else
        echo -e "${green}当前 PasswordAuthentication 配置: ${current_password_auth:-默认 (no)}${no_color}"
    fi
    echo -e "${yellow}选择 PasswordAuthentication 的配置: ${no_color}"
    echo -e "${red}1. 允许使用密码登录 (PasswordAuthentication yes)${no_color}"
    echo -e "${green}2. 禁止使用密码登录 (PasswordAuthentication no)${no_color}"
    read -r -p "输入选项 (1/2/其他不修改): " password_auth_choice

    case $password_auth_choice in
        1)
            sudo sed -i '/^#*PasswordAuthentication/c\PasswordAuthentication yes' /etc/ssh/sshd_config
            echo -e "PasswordAuthentication 设置为 ${red}yes${no_color}"
            ;;
        2)
            sudo sed -i '/^#*PasswordAuthentication/c\PasswordAuthentication no' /etc/ssh/sshd_config
            echo -e "PasswordAuthentication 设置为 ${green}no${no_color}"
            ;;
        *)
            # No changes
            echo -e "${blue}PasswordAuthentication 未改变${no_color}"
            ;;
    esac

    # Restart SSH service to apply changes
    sudo systemctl restart sshd
    echo
}

# 函数：添加私钥到 ssh-agent
function add_key_to_ssh_agent() {
    echo -e "${green}Select a user to add their ${red}private${green} key to ssh-agent:${no_color}"
    local current_user_keys
    mapfile -t current_user_keys < <(find "$HOME/.ssh" -name "*id_ed25519*" -exec basename {} \;)
    if [ ${#current_user_keys[@]} -gt 0 ]; then
        echo -e "${yellow}SSH keys found in the current user's .ssh directory:${no_color}"
        for i in "${!current_user_keys[@]}"; do
            echo "$((i+1)). ${current_user_keys[i]}"
        done
        echo -ne "${yellow}Choose a key number, or 'q' to select a different user: ${no_color}"
        read -r key_choice
        echo
        if [[ $key_choice =~ ^[0-9]+$ ]] && [ "$key_choice" -le "${#current_user_keys[@]}" ]; then
            local selected_key="$HOME/.ssh/${current_user_keys[$((key_choice-1))]}"
            ssh-add "$selected_key"
            echo -e "${blue}Added ${red}private${blue} key to ssh-agent successfully${no_color}"
            return
        elif [[ $key_choice == 'q' ]]; then
            echo -e "${yellow}Selecting a different user...${no_color}"
        else
            echo -e "${red}Invalid input, please try again.${no_color}"
        fi
    else
        echo -e "${red}No SSH keys found in the current user's .ssh directory.${no_color}"
    fi

    local users
    mapfile -t users < <(awk -F: '{ if ($7 ~ /^(\/bin\/bash|\/bin\/sh)$/) print $1 }' /etc/passwd)
    for i in "${!users[@]}"; do
        echo "$((i+1)). ${users[i]}"
    done
    echo -ne "${yellow}Choose a user number (or 'q' to exit): ${no_color}"
    read -r user_choice
    echo
    if [[ $user_choice =~ ^[0-9]+$ ]] && [ "$user_choice" -le "${#users[@]}" ]; then
        local selected_user="${users[$((user_choice-1))]}"
        local user_ssh_keys
        mapfile -t user_ssh_keys < <(find "/home/$selected_user/.ssh" -name "*" -exec basename {} \;)
        if [ ${#user_ssh_keys[@]} -gt 0 ]; then
            echo -e "${yellow}Select a key from $selected_user's .ssh directory:${no_color}"
            for i in "${!user_ssh_keys[@]}"; do
                echo "$((i+1)). ${user_ssh_keys[i]}"
            done
            echo -ne "${yellow}Choose a key number: ${no_color}"
            read -r key_choice
            echo
            if [[ $key_choice =~ ^[0-9]+$ ]] && [ "$key_choice" -le "${#user_ssh_keys[@]}" ]; then
                local selected_key="/home/$selected_user/.ssh/${user_ssh_keys[$((key_choice-1))]}"
                ssh-add "$selected_key"
                echo -e "${blue}Added private key to ssh-agent successfully${no_color}"
                return
            else
                echo -e "${red}Invalid input, please try again.${no_color}"
            fi
        else
            echo -e "${red}No SSH keys found for $selected_user.${no_color}"
        fi
    elif [[ $user_choice == 'q' ]]; then
        return
    else
        echo -e "${red}Invalid input, please try again.${no_color}"
    fi
}

# 执行所有函数
init_ssh
add_user
show_and_delete_user
check_ssh_config
add_key_to_ssh_agent

echo
echo -e "${red}You should manually execute the following code to bind the ssh-agent:${no_color}"
echo
echo -e "${green}SSH_AGENT_PID=$SSH_AGENT_PID; export SSH_AGENT_PID;${no_color}"
echo -e "${green}SSH_AUTH_SOCK=$SSH_AUTH_SOCK; export SSH_AUTH_SOCK;${no_color}"
echo
echo -e "${blue}You can run ${no_color}${green}ssh-add -l${no_color}${blue} to check if ssh-agent is successfully bound${no_color}"
echo
echo -e "${blue}and use ${green}ssh -T git@github.com${blue} to test github connection!${no_color}"
echo
