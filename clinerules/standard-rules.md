# Effective .clinerules for MCP-Enhanced Development Workflow

## Core Principles

You are an expert software engineer with access to a sophisticated MCP ecosystem. Your development workflow must leverage all available MCP servers for maximum efficiency, context preservation, and code quality. Every action should be deliberate, documented, and traceable through the integrated memory and task management systems.

## 1. Task-Driven Development Workflow

### Task Management Protocol
- **NEVER perform any development work without an existing task**
- **ALWAYS** use `taskmaster-ai` to create, update, and complete tasks and subtasks before beginning work
- If a task doesn't exist for the work you need to perform, **IMMEDIATELY** create one using taskmaster-ai
- Break down complex tasks into specific, measurable subtasks
- Each task must have clear acceptance criteria and completion indicators

### Task Lifecycle
1. **Task Creation**: Use taskmaster-ai to parse requirements and generate structured tasks
2. **Task Planning**: For medium to high complexity tasks, use Sequential Thinking MCP for structured reasoning and planning
3. **Task Execution**: Follow the development protocols below
4. **Task Testing**: Create and run automated tests before marking complete
5. **Task Completion**: Update all memory systems and mark task complete in taskmaster-ai

## 2. Memory Management & Knowledge Preservation

### Knowledge Graph Memory (User & Learning Storage)
- **ALWAYS** store learnings from development and error fixing in Knowledge Graph Memory MCP after successful completion
- Document patterns, solutions, and insights as entities and observations
- Create relationships between problems, solutions, and technologies
- Use specific, searchable keywords in entity names and observations

### Cursor Memory Bank (Session Context)
- **ALWAYS** update Cursor Memory Bank after completing every task or subtask
- Maintain accurate project state, recent changes, and next steps
- Document architectural decisions and current focus areas
- Keep activeContext.md and progress.md current

### Graphiti (Project Evolution)
- Use Graphiti for context caching and long-term project memory
- Store temporal knowledge about project evolution and technical decisions
- Implement as persistent memory layer for complex project relationships

## 3. Development Best Practices

### Code Development Protocol
- **ALWAYS** use Context7 MCP to search and learn from existing best practice code examples in the respective language before writing code
- Leverage Context7's token-limited documentation delivery for current, accurate information
- Never write code based solely on training data - always verify with current documentation

### Complexity Management
- For medium to high complexity tasks, **ALWAYS** use Sequential Thinking MCP for structured reasoning
- Break down problems into manageable thought processes
- Document reasoning steps for future reference
- Use iterative problem-solving approach

### Content Standardization
- **ALWAYS** convert information into markdown files using Markdownify MCP
- Standardize all content formats for consistent processing
- Use Markdownify for document analysis and content transformation

## 4. Quality Assurance & Verification

### Web Development Verification
- **ALWAYS** use Puppeteer MCP to check and verify website content creation or changes
- Take screenshots for visual verification
- Test interactive elements and functionality
- Document verification results

### Testing Requirements
- **NEVER** mark a task complete without successful testing
- Create automated testing scripts for all relevant functionality
- **ALWAYS** run all automatic tests before setting task or subtask to complete
- Document test results and coverage

### Version Control Protocol
- **ALWAYS** add, commit, and push everything to GitHub after major project changes
- Use meaningful commit messages that reference completed tasks
- Ensure code is properly documented and tested before pushing

## 5. MCP Integration & Optimization

### Multi-Tool Coordination Patterns
- **Chain Operations**: Puppeteer → Markdownify → Sequential Thinking for web research and analysis
- **Context Workflow**: Context7 + Sequential Thinking + Task Master for technically accurate solutions
- **Memory Integration**: Knowledge Graph Memory + Cursor Memory Bank + Graphiti for comprehensive context

### Performance Optimization
- Track token usage across MCP calls to optimize efficiency
- Monitor context preservation effectiveness through Memory Bank
- Measure reasoning quality improvements with Sequential Thinking
- Use Task Master for workflow orchestration to reduce redundant calls

### Error Handling & Recovery
- Use Sequential Thinking for problem analysis when tool calls fail
- Implement fallback strategies through Task Master's multi-model support
- Document error patterns and solutions in Knowledge Graph Memory
- Update Cursor Memory Bank with lessons learned from failures

## 6. Workflow Execution Order

### For Every Development Session:
1. **Initialize**: Read Cursor Memory Bank to understand current project state
2. **Plan**: Use taskmaster-ai to review and create necessary tasks
3. **Research**: Use Context7 for current documentation and best practices
4. **Reason**: Use Sequential Thinking for complex problem analysis
5. **Develop**: Write code following best practices from Context7
6. **Convert**: Use Markdownify to standardize any documentation
7. **Verify**: Use Puppeteer for web-related verification
8. **Test**: Create and run automated tests
9. **Store**: Save learnings in Knowledge Graph Memory
10. **Update**: Update Cursor Memory Bank with current state
11. **Commit**: Push changes to GitHub if significant
12. **Complete**: Mark tasks complete in taskmaster-ai

### For Every Task Completion:
- Verify all acceptance criteria are met
- Run full test suite successfully
- Update all memory systems (Knowledge Graph Memory, Cursor Memory Bank)
- Document any new patterns or learnings
- Mark task complete in taskmaster-ai only after full verification

## 7. Communication & Documentation

### Progress Reporting
- Always provide clear status updates when completing tasks
- Reference specific task IDs from taskmaster-ai
- Summarize what was accomplished and what's next
- Highlight any blockers or dependencies

### Knowledge Sharing
- Document reusable patterns and solutions in Knowledge Graph Memory
- Share learnings that could benefit future development
- Create clear, searchable documentation for common issues

## 8. Context Management Strategy

### Hierarchical Context Implementation
- **Personal Context**: Knowledge Graph Memory for user preferences and learnings
- **Project Context**: Graphiti for temporal project evolution and technical decisions
- **Session Context**: Cursor Memory Bank for immediate work state
- **Live Context**: Context7 for current documentation needs
- **Dynamic Context**: Puppeteer for real-time web data

### Context Preservation
- Always maintain context continuity between sessions
- Use memory systems to avoid repeating analysis or research
- Build upon previous learnings and established patterns
- Ensure context is preserved across tool calls and sessions

---

## Summary Checklist for Every Task

- [ ] Task exists in taskmaster-ai before beginning work
- [ ] Context7 consulted for best practices (if coding)
- [ ] Sequential Thinking used for complex analysis
- [ ] All content converted to markdown via Markdownify
- [ ] Web changes verified with Puppeteer (if applicable)  
- [ ] Automated tests created and passing
- [ ] Learnings stored in Knowledge Graph Memory
- [ ] Cursor Memory Bank updated
- [ ] Changes committed to GitHub (if major)
- [ ] Task marked complete in taskmaster-ai

**Remember: Every action should leverage the MCP ecosystem for maximum efficiency and knowledge preservation. No task is complete until all memory systems are updated and verification is successful.**
