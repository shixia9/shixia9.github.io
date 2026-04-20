---
categories:
  - AI
  - Agent
tags:
  - ai
  - typescript
  - claude
  - agent
---
> 2026年3月31日，Anthropic在发布Claude Code CLI v2.1.88版本时，因打包配置疏忽，将一个59.8MB的Source Map文件上传至npm平台
> 
> 在它的这份源码拷贝中，注意到Claude Code CLI里一个有意思的功能——**KAIROS**模块，或者可以说是「梦模式」？
> 
> KAIROS，希腊语，意为“恰当的时机"，在源码中被提及多次，是Claude Code从“被动问答工具"向“主动持续助手"演进的核心架构
> 
> **参考**：[RishabhK103/claude-code](https://github.com/RishabhK103/claude-code)

## 0. Claude Code源码总览

```plaintext
src/
├── main.tsx              # CLI 主入口 — Commander.js 命令定义与启动编排
├── entrypoints/          # 多入口：cli.tsx, init.ts, mcp.ts, sdk/
├── QueryEngine.ts        # 查询引擎 — 管理对话生命周期
├── query.ts              # 核心查询循环 — API 调用 + 工具执行的状态机
├── Tool.ts               # 工具抽象层 — Tool<I,O,P> 泛型定义
├── tools.ts              # 工具注册表 — 动态组装工具池
├── tools/                # 40+ 工具实现：BashTool, FileEditTool, AgentTool...
├── types/                # 纯类型文件 — 打破循环依赖
├── state/                # 应用状态管理 — AppState, store
├── services/             # 外部服务交互
│   ├── api/              # Anthropic API 客户端
│   ├── mcp/              # MCP 协议实现
│   ├── compact/          # 上下文压缩服务
│   ├── analytics/        # 遥测与分析
│   └── tools/            # 工具编排引擎（并发执行）
├── hooks/                # React hooks（useCanUseTool 等）
├── components/           # Ink UI 组件
├── screens/              # TUI 页面（权限对话框、设置等）
├── commands/             # 斜杠命令系统
├── skills/               # 技能系统（可扩展的命令集）
├── plugins/              # 插件系统
├── coordinator/          # 多 Agent 协调器
├── context/              # 上下文管理
├── migrations/           # 配置迁移脚本
├── utils/                # 工具函数集（最大的目录）
│   ├── permissions/      # 权限子系统
│   ├── model/            # 模型选择与配置
│   ├── settings/         # 分层配置系统
│   ├── sandbox/          # 命令沙箱
│   └── ...
├── bootstrap/            # 启动状态管理
├── remote/               # 远程会话管理
├── server/               # Direct Connect 服务端
├── assistant/            # 助手模式（KAIROS）
└── voice/                # 语音输入
```

Claude Code，以下称CC，整体结构模块众多，包含了30+顶层模块，具体可以划分为5个核心层次，每层之间下层向上层提供抽象，上层依赖下层具体实现。

+ **layer 1 CLI&UI**：最顶层向外提供交互以及终端渲染等，核心包括`main.tsx`使用`Commander.js`定义完整的CLI接口；`REPL.tsx`提供交互式终端命令行REPL（Read–Eval–Print Loop）交互界面。
+ **layer 2 Query Engine**：核心代码包括`QueryEngine.ts`、`query.ts`、`queryContext.ts`分别处理会话生命周期管理、核心查询循环、系统提示词组装。
+ **layer 3 Tools**：主要定义了工具的抽象接口和相关执行引擎，包括`tools.ts`工具注册表（通过`bun:bundle`的`feature`进行死代码消除，控制不同的角色或者模式下使用不同的工具）以及`Tool.ts`工具抽象接口，在这之上实现`toolExecution.ts`单工具执行以及`toolOrchestration.ts`并发控制（工具被分为并发安全和串行执行两种模式，read-only的工具一般就是并发执行，而non-read-only为串行执行）
```typescript
// src/tools.ts

// 大量使用 feature() 函数进行编译时死代码消除(Dead Code Elimination)
// Check if a feature flag is enabled at compile time.
// This function is replaced with a boolean literal ( or ) at bundle time, enabling dead-code elimination.
// The bundler will remove unreachable branches.    ----https://bun.com/reference/bun/bundle/feature
const SleepTool =
  feature('PROACTIVE') || feature('KAIROS')
    ? require('./tools/SleepTool/SleepTool.js').SleepTool
    : null
const cronTools = feature('AGENT_TRIGGERS')
  ? [
      require('./tools/ScheduleCronTool/CronCreateTool.js').CronCreateTool,
      require('./tools/ScheduleCronTool/CronDeleteTool.js').CronDeleteTool,
      require('./tools/ScheduleCronTool/CronListTool.js').CronListTool,
    ]
  : []
const RemoteTriggerTool = feature('AGENT_TRIGGERS_REMOTE')
  ? require('./tools/RemoteTriggerTool/RemoteTriggerTool.js').RemoteTriggerTool
  : null
```

```typescript
// src/services/tools/toolOrchestration.ts

export async function* runTools(
  toolUseMessages: ToolUseBlock[],  // LLM输出的tool call列表
  assistantMessages: AssistantMessage[],  // 当前对话上下文中的 assistant 历史消息
  canUseTool: CanUseToolFn,  // 工具权限检查函数
  toolUseContext: ToolUseContext,  // 工具执行的共享上下文
): AsyncGenerator<MessageUpdate, void> {
  let currentContext = toolUseContext  // 后续工具的执行都会逐步修改这个context
  // partitionToolCalls(): 将工具拆分为多个batch，多个连续的read-only，或者单个non-read-only工具
  for (const { isConcurrencySafe, blocks } of partitionToolCalls(
    toolUseMessages,
    currentContext,
  )) {
    // 并发安全的工具（Glob、Grep、FileRead...）并行执行
    if (isConcurrencySafe) {
      // 暂存context修改：并发执行时不能直接修改共享context
      const queuedContextModifiers: Record<
        string,
        ((context: ToolUseContext) => ToolUseContext)[]
      > = {}
      // Run read-only batch concurrently
      for await (const update of runToolsConcurrently(
        blocks,
        assistantMessages,
        canUseTool,
        currentContext,
      )) {
        if (update.contextModifier) {
          const { toolUseID, modifyContext } = update.contextModifier
          if (!queuedContextModifiers[toolUseID]) {
            queuedContextModifiers[toolUseID] = []
          }
          queuedContextModifiers[toolUseID].push(modifyContext)
        }
        // 实时流式返回，此时context还没修改
        yield {
          message: update.message,
          newContext: currentContext,
        }
      }
      // 批次结束后统一更新context
      for (const block of blocks) {
        const modifiers = queuedContextModifiers[block.id]
        if (!modifiers) {
          continue
        }
        // 按照tool call的顺序应用modifier
        for (const modifier of modifiers) {
          currentContext = modifier(currentContext)
        }
      }
      // 最终context更新通知
      yield { newContext: currentContext }
    } else {
      // 非并发安全的工具串行执行
      // Run non-read-only batch serially
      for await (const update of runToolsSerially(
        blocks,
        assistantMessages,
        canUseTool,
        currentContext,
      )) {
        // 执行完一个就更新一次context
        if (update.newContext) {
          currentContext = update.newContext
        }
        yield {
          message: update.message,
          newContext: currentContext,
        }
      }
    }
  }
}
```
+ **layer 4 Agent**：这一层主要围绕agent，包括支持agent嵌套以及任务管理，`src/tools/AgentTool/`目录下就包含了子agent创建，每个子agent拥有独立的`QueryEngine`实例，实现递归式的任务分解；以及`coordinatorMode.ts`下多agent协调
	![[img1-agent-tools-directory.png]]
	CC内部提供的agent包括：
	1. `claudeCodeGuideAgent`：专门回答CC/SDK/API使用问题的内置Agent，并根据用户环境动态生成system prompt和工具能力；
	2. `exploreAgent`：一个高速只读的专门用于搜索代码库的子代理，通过grep/glob/read等工具快速定位代码信息，并将结果返回给主 Agent进行分析，有明确的禁止操作，只提供只读权限，核心能力被限制为3个：文件搜索、内容搜索、文件阅读。而且这个agent被定义至少进行3次查询`export const EXPLORE_AGENT_MIN_QUERIES = 3`，防止只搜索一次就返回；通过定义一段提示词文本`EXPLORE_WHEN_TO_USE`告诉agent执行的时机，太长了就不贴了，包括找文件、搜代码、理解代码等这些场景，同时调用时还需要指定3个level，`quick`、`medium`以及`very thorough`；
	3. `generalPurposeAgent`：它是一个通用目标子代理，代码很短，但它是一个能力较完整的“研究型子代理”，用于处理复杂任务或代码探索。其主要是通过一个共享前缀`SHARED_PREFIX`以及共享行为指南`SHARED_GUIDELINES`这两块提示词，先是定义所有行为的基本目标，再用prompt规定agent的优势，说人话就是这个agent擅长大规模代码搜索、系统架构分析、复杂问题调查、多步骤任务；然后通过`getGeneralPurposeSystemPrompt()`组装系统提示词，并允许这个agent使用所有tool`tools: ['*']`；
	4. `planAgent`（任务规划）、`statuslineSetup`（配置工具）、`verificationAgent`（结果验证）：剩下的agent与上面的类似，也是通过一大段prompt定义它的能力组合，每个`BuiltInAgentDefinition`就是一种Agent角色+能力+使用场景+系统提示词的组合，主Agent在需要时调用这些Agent来完成任务；核心字段：
	```typescript
type BuiltInAgentDefinition = {
	agentType: string  // Agent名称
	whenToUse: string  // 什么时候调用
	tools?: string[]  // 允许使用的工具
	disallowedTools?: string[]  // 禁止使用的工具
	model?: string  // 使用的模型
	getSystemPrompt: () => string  // Agent的系统提示词
}
	```
+ **layer 5 Protocol&Services**：基础设施层，包括API客户端、MCP协议的实现、权限引擎和上下文压缩服务，具体为`services/`包下的`api/`、`mcp/`、`permission/`以及`compact/`

![[mermaid-diagram-2026-04-03-181219.png]]

在一次对话的流程中，系统内部的执行分为多个阶段：
### 0.1 消息组装

#### 0.1.1 REPL

`REPL.tsx`也就是用户在终端和CC对话的整个UI、输入处理、消息渲染、状态管理的完整实现，大约5k行的代码，整体的流程大致为：用户输入处理、消息列表、与agent通信、token预算管理、多agent协作、权限管理、通知系统、UI渲染。

*\*这里只着重看看agent通信与多agent协作部分，其它的方法没有细细研究..*

| 名称           | 实体                               | 核心方法/类                                                                | 职责                              |
| ------------ | -------------------------------- | --------------------------------------------------------------------- | ------------------------------- |
| 主线程Agent     | Main Thread                      | `mainThreadAgentDefinition`, `useMainLoopModel()`                     | 负责用户交互、Prompt输入、工具调用协调          |
| 子Agent       | Local Agent, In-process Teammate | `LocalAgentTask`, `InProcessTeammateTask`                             | 独立执行子任务，可在进程内或后台运行              |
| Swarm Worker | Swarm Worker                     | `isSwarmWorker()`, `pendingWorkerRequest`, `workerSandboxPermissions` | 分布式Worker，通过Mailbox通信           |
| Remote Agent | Remote Agent                     | `remoteSessionConfig`, `restoreRemoteAgentTasks`                      | 通过SSH、Direct Connect等运行的远程Agent |
| 任务调度         | Task System                      | `tasks`(AppState), `TaskListV2`, `useTasksV2WithCollapseEffect`       | 统一管理所有Agent的生命周期                |

在CC这一套Multi-Agent结构中，由主线程做大脑，多个子agent做执行单元，每个agent都有各自独立的工作集、sandbox权限、文件历史，而且agent可完全后台运行，主REPL不阻塞。在REPL中，所有子Agent不会直接与LLM挂钩，而是通过构造`AgentTask`，定义两类任务：
+ 本地agent处理的`LocalAgentTask`
+ 子agent处理的`InProcessTeammateTask`

```typescript
import { isLocalAgentTask, queuePendingMessage, appendMessageToLocalAgent, type LocalAgentTaskState } 
from '../tasks/LocalAgentTask/LocalAgentTask.js';
import { injectUserMessageToTeammate, getAllInProcessTeammateTasks } from '../tasks/InProcessTeammateTask/InProcessTeammateTask.js';
```

对于收到的本地agent任务`LocalAgentTask`，当终端收到用户输入时，会把用户的消息加入到agent的message history；如果当前agent正在执行任务，新消息不会立即执行，而是加入到`queuePendingMessage`等待队列，避免agent的推理中途被打断；如果agent不在运行状态，这里触发agent runtime推理，通过`resumeAgentBackground()`恢复并继续执行一个后台subagent任务，具体为：
1. 从磁盘恢复agent的历史会话`transcript`
2. 还原agent执行上下文（system prompt, worktree, tools, state）
3. 重新注册agent任务
4. 在后台启动agent生命周期Agent Loop
5. 让该后台agent继续推理，调用工具并产生结果

如果收到的是子agent处理的任务`InProcessTeammateTask`，就会通过`injectUserMessageToTeammate()`将用户消息注入到teammate的待处理队列中，CC对于teammate的定义：

> *"InProcessTeammateTask - Manages in-process teammate lifecycle
>  This component implements the Task interface for in-process teammates.
>  Unlike LocalAgentTask (background agents), in-process teammates:
>  1. Run in the same Node.js process using AsyncLocalStorage for isolation
>  2. Have team-aware identity (agentName@teamName)
>  3. Support plan mode approval flow
>  4. Can be idle (waiting for work) or active (processing)"*

这类特殊的agent，in-process teammate，与之前的`LocalAgentTask`后台subagent不同，它是执行在同一nodejs进程当中，用来构建一系列协作agent（Agent Swarm）。

```typescript
const onAgentSubmit = useCallback(async (input: string, task: InProcessTeammateTaskState | LocalAgentTaskState, helpers: PromptInputHelpers) => {
	if (isLocalAgentTask(task)) {
	  appendMessageToLocalAgent(task.id, createUserMessage({
		content: input
	  }), setAppState);
	  if (task.status === 'running') {
		queuePendingMessage(task.id, input, setAppState);
	  } else {
		void resumeAgentBackground({
		  agentId: task.id,
		  prompt: input,
		  toolUseContext: getToolUseContext(messagesRef.current, [], new AbortController(), mainLoopModel),
		  canUseTool
		}).catch(err => {
		  logForDebugging(`resumeAgentBackground failed: ${errorMessage(err)}`);
		  addNotification({
			key: `resume-agent-failed-${task.id}`,
			jsx: <Text color="error">
				  Failed to resume agent: {errorMessage(err)}
				</Text>,
			priority: 'low'
		  });
		});
	  }
	} else {
	  injectUserMessageToTeammate(task.id, input, setAppState);
	}
	setInputValue('');
	helpers.setCursorOffset(0);
	helpers.clearBuffer();
}, [setAppState, setInputValue, getToolUseContext, canUseTool, mainLoopModel, addNotification]);
```
#### 0.1.2 QueryEngine

> *"QueryEngine owns the query lifecycle and session state for a conversation.
> It extracts the core logic from ask() into a standalone class that can be used by both the headless/SDK path and (in a future phase) the REPL.
> One QueryEngine per conversation. Each submitMessage() call starts a new turn within the same conversation. State (messages, file cache, usage, etc.) persists across turns."*

QueryEngine简单来说就是CC专门为非交互式或者SDK等场景设计的查询引擎，它的核心作用可以简单概括为：**负责管理一次完整会话conversation的生命周期和状态，把一个prompt转成一连串规范的SDKMessage，同时在多次调用间持久化消息历史、文件缓存、token用量、权限记录等状态**

QueryEngine最核心的方法就是`submitMessage()`，它通过输入一个prompt（string或者是ContentBlockParam数组）返回一个异步生成器`AsyncGenerator<SDKMessage>`，即流式返回系统初始化消息assistant回复、工具结果、compact boundary、最终result等，把整个CC查询流程封装为一个SDK格式的消息流；

当`QueryEngine.submitMessage()`被调用时，系统会去组装系统提示词，系统提示由多个部分组成：默认提示（包含角色定义、工具使用指南、安全规则）、用户上下文（git状态、工作目录信息）、系统上下文（操作系统、shell 类型），以及可选的记忆文件和自定义追加内容。

```typescript
async *submitMessage(...) {
  // 1. 前置准备
  this.discoveredSkillNames.clear();
  setCwd(cwd);
  const persistSession = !isSessionPersistenceDisabled();

  // 2. 包装 canUseTool（记录所有可用工具）
  const wrappedCanUseTool = async (...) => { ... }

  // 3. 初始化 model、thinkingConfig、appState
  const initialMainLoopModel = ...
  const initialThinkingConfig = ...

  // 4. 构建系统提示，获取系统提示的各个组成部分
  const { defaultSystemPrompt, userContext, systemContext } = 
    await fetchSystemPromptParts({ ... });
  
  const memoryMechanicsPrompt = ... // 如果有 CLAUDE_COWORK_MEMORY_PATH_OVERRIDE
  // 组装最终的系统提示
  const systemPrompt = asSystemPrompt([customPrompt, memoryMechanicsPrompt, appendSystemPrompt]);

  // 5. 构建 processUserInputContext（上下文容器）
  let processUserInputContext: ProcessUserInputContext = { ... }

  // 6. 处理 orphanedPermission
  if (orphanedPermission && !this.hasHandledOrphanedPermission) { ... }

  // 7. 处理用户输入
  const {
    messages: messagesFromUserInput,
    shouldQuery,
    allowedTools,
    model: modelFromUserInput,
    resultText,
  } = await processUserInput({ input: prompt, ... });

  // 8. 追加消息+立即持久化 transcript
  this.mutableMessages.push(...messagesFromUserInput);
  if (persistSession) {
    await recordTranscript(messages);   // 用户消息先落盘
  }

  // 9. 如果是纯 slash command（shouldQuery === false）
  if (!shouldQuery) {
    // 直接 yield 本地命令输出 + result 消息并返回
    ... 
    yield { type: 'result', subtype: 'success', ... };
    return;
  }

  // 10. 否则进入真正的 query 循环（query.ts）
  for await (const message of query({ 
    messages,
    systemPrompt,
    userContext,
    systemContext,
    canUseTool: wrappedCanUseTool,
    toolUseContext: processUserInputContext,
    ...
  })) {
    // 11. 消息分类处理 + yield SDK 格式
    if (message.type === 'assistant' || 'user' || 'compact_boundary') {
      messages.push(message);
      if (persistSession) recordTranscript(...);
    }

    switch (message.type) {
      case 'assistant':   yield* normalizeMessage(message); break;
      case 'progress':    yield* normalizeMessage(message); break;
      case 'user':        yield* normalizeMessage(message); break;
      case 'attachment':  // 结构化输出、max_turns_reached 等
      case 'system':      // compact_boundary、api_error 等
      case 'tool_use_summary':
      case 'stream_event': // 如果 includePartialMessages
        ...
    }

    // 各种终止条件
    if (maxBudgetUsd 超限) yield error_max_budget_usd 并 return;
    if (structured output 重试超限) yield error_max_structured_output_retries 并 return;
  }

  // 12. 循环结束 → 最终 result 消息
  const result = messages.findLast(...);
  if (!isResultSuccessful(result, lastStopReason)) {
    yield { type: 'result', subtype: 'error_during_execution', ... };
  } else {
    yield { type: 'result', subtype: 'success', result: textResult, ... };
  }
}
```
### 0.2 循环查询

通过看了REPL以及QueryEngine源码可以发现，系统的核心循环查询方法来自于`query.ts`的`query()`方法，它也是通过返回一个异步生成器`AsyncGenerator`实现了API调用和工具执行的交替循环

```typescript
export async function* query(
  params: QueryParams,
): AsyncGenerator<
  | StreamEvent
  | RequestStartEvent
  | Message
  | TombstoneMessage
  | ToolUseSummaryMessage,
  Terminal
> {
  const consumedCommandUuids: string[] = []
  const terminal = yield* queryLoop(params, consumedCommandUuids)
  for (const uuid of consumedCommandUuids) {
    notifyCommandLifecycle(uuid, 'completed')
  }
  return terminal
}
```

可以看出`query()`及其调用的`queryLoop()`是CC最核心最复杂的查询引擎实现，它负责了整个多轮Agent对话的完整生命周期，从用户prompt到最终结果，包括上下文管理、API 流式调用、工具执行、自动压缩、智能恢复等几乎所有智能行为；

当`queryLoop()`正常结束后，通知所有被消费的命令`notifyCommandLifecycle()`，最终返回一个`Terminal`对象；而`queryLoop()`就是整个文件的灵魂，一个while (true) 无限循环，代表一次完整的Agentic Turn，其中可能包含多次模型调用及工具执行，
### 0.3 工具执行

### 0.4 流式输出