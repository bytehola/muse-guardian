# muse-guardian

给 Muse.ai 沙盒装上探针、Hermes、保活和重建脚本，以及 **MuseAutoApprove**（审批自动批准器）的 SKILL。

## 使用

```
帮我安装 `https://raw.githubusercontent.com/bytehola/muse-guardian/refs/heads/main/SKILL.md`。
```

安装后 Agent 会按手册步骤部署以下组件：

| 组件 | 作用 |
|---|---|
| cf-probe 探针 | 向 CF 后台上报沙盒状态 |
| Hermes  | 操控沙盒里的 AI Agent |
| 三层保活 | 看门狗 + 平台巡检 + 开机钩子，重建后自动恢复 |
| **MuseAutoApprove** | 自动批准沙盒的外联审批卡片，访问新域名不再等人点"允许" |

## 效果

<img width="843" height="636" alt="66695ffdbcaa3b97b3f7138644d2aead" src="https://github.com/user-attachments/assets/193a0521-b6d7-47b3-8ee3-2715f337dd60" />
