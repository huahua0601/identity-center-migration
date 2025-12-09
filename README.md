# IAM User Group to AWS Identity Center Migration Tool

这个工具用于将 AWS IAM User Groups 及其关联的 Policies 迁移到 AWS Identity Center (原 AWS SSO) 的 Groups 和 Permission Sets。

## 功能特点

- ✅ 导出 IAM Groups 及其 attached/inline policies
- ✅ 在 Identity Center 中创建对应的 Groups
- ✅ 将 IAM Policies 转换为 Permission Sets
- ✅ 支持 AWS Managed Policies 和 Customer Managed Policies
- ✅ 支持 Inline Policies 合并
- ✅ 自动将 Permission Sets 分配给 Groups
- ✅ 支持多账户分配
- ✅ Dry Run 模式预览变更
- ✅ 详细的迁移日志

## 前置条件

1. **AWS Identity Center 已启用**
   - 在 AWS Organizations 管理账户中启用 Identity Center
   
2. **IAM 权限要求**
   执行迁移的用户/角色需要以下权限：
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": [
                   "iam:ListGroups",
                   "iam:GetGroup",
                   "iam:ListAttachedGroupPolicies",
                   "iam:ListGroupPolicies",
                   "iam:GetGroupPolicy",
                   "iam:GetPolicy",
                   "iam:GetPolicyVersion"
               ],
               "Resource": "*"
           },
           {
               "Effect": "Allow",
               "Action": [
                   "sso:ListInstances",
                   "sso:CreatePermissionSet",
                   "sso:DescribePermissionSet",
                   "sso:ListPermissionSets",
                   "sso:PutInlinePolicyToPermissionSet",
                   "sso:AttachManagedPolicyToPermissionSet",
                   "sso:AttachCustomerManagedPolicyReferenceToPermissionSet",
                   "sso:CreateAccountAssignment"
               ],
               "Resource": "*"
           },
           {
               "Effect": "Allow",
               "Action": [
                   "identitystore:CreateGroup",
                   "identitystore:ListGroups"
               ],
               "Resource": "*"
           },
           {
               "Effect": "Allow",
               "Action": [
                   "organizations:ListAccounts"
               ],
               "Resource": "*"
           }
       ]
   }
   ```

3. **Python 环境**
   - Python 3.8+
   - boto3

## 安装

```bash
cd identity-center-migration
pip install -r requirements.txt
```

## 使用方法

### 1. 仅导出 IAM Groups（不做任何更改）

首先导出现有 IAM Groups 进行审查：

```bash
python migrate_iam_to_identity_center.py --export-only
```

这将生成 `iam_groups_export.json` 文件，包含所有 IAM Groups 及其 policies 的详细信息。

### 2. Dry Run 模式（模拟迁移）

在实际迁移前，使用 dry-run 模式查看将要执行的操作：

```bash
python migrate_iam_to_identity_center.py --dry-run
```

### 3. 迁移特定的 Groups

只迁移指定的 IAM Groups：

```bash
python migrate_iam_to_identity_center.py --groups Developers Admins DBAs
```

### 4. 指定目标账户

将 Permission Sets 分配给特定的 AWS 账户：

```bash
python migrate_iam_to_identity_center.py --accounts 123456789012 987654321098
```

### 5. 完整迁移

迁移所有 IAM Groups 到所有组织账户：

```bash
python migrate_iam_to_identity_center.py
```

### 6. 分离的 Permission Sets

默认情况下，每个 Group 的所有 policies 会合并为一个 Permission Set。
如果希望为每个 policy 创建单独的 Permission Set：

```bash
python migrate_iam_to_identity_center.py --separate-permission-sets
```

### 指定 Region

如果 Identity Center 不在 us-east-1：

```bash
python migrate_iam_to_identity_center.py --region ap-southeast-1
```

## 命令行参数

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--region` | `-r` | Identity Center 所在的 AWS 区域 | us-east-1 |
| `--groups` | `-g` | 指定要迁移的 IAM Group 名称 | 所有 groups |
| `--accounts` | `-a` | 指定目标 AWS 账户 ID | 所有组织账户 |
| `--dry-run` | `-d` | 模拟运行，不做实际更改 | False |
| `--export-only` | `-e` | 仅导出 IAM groups 信息 | False |
| `--separate-permission-sets` | `-s` | 为每个 policy 创建单独的 Permission Set | False |

## 迁移映射关系

| IAM 资源 | Identity Center 资源 |
|----------|----------------------|
| IAM Group | Identity Center Group |
| IAM Managed Policy (AWS) | Permission Set with Managed Policy |
| IAM Managed Policy (Customer) | Permission Set with Customer Managed Policy Reference 或 Inline Policy |
| IAM Inline Policy | Permission Set with Inline Policy |

## 输出文件

- `iam_groups_export.json` - 导出的 IAM Groups 数据
- `migration_YYYYMMDD_HHMMSS.log` - 详细迁移日志

## 迁移后步骤

1. **验证 Identity Center Groups**
   - 登录 AWS Identity Center 控制台
   - 检查创建的 Groups 和 Permission Sets

2. **添加用户到 Groups**
   - 脚本不会自动迁移用户
   - 需要手动将用户添加到 Identity Center Groups
   - 或使用 SCIM 从外部 IdP 同步用户

3. **测试权限**
   - 让测试用户使用新的 Identity Center Groups 登录
   - 验证权限是否正确

4. **清理旧的 IAM Groups**（可选）
   - 确认迁移成功后，可以考虑删除旧的 IAM Groups

## 注意事项

⚠️ **重要提醒**：

1. 此脚本需要在 AWS Organizations 管理账户中运行
2. Identity Center 必须已经启用
3. 建议先在测试环境中验证
4. 某些复杂的 IAM 策略可能需要手动调整
5. Permission Set 名称最长 32 个字符
6. Inline Policy 最大 10240 字节

## 故障排除

### 常见错误

**1. "No Identity Center instance found"**
- 确保 Identity Center 已在您的组织中启用
- 检查区域是否正确

**2. "Access Denied"**
- 确认执行用户有足够的 IAM 权限
- 检查是否在管理账户中运行

**3. "Policy size exceeds limit"**
- 合并后的 inline policy 超过大小限制
- 使用 `--separate-permission-sets` 参数分离策略

## License

MIT License

