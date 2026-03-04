"""
Multi-Agent Orchestrator for PRISM

Coordinates multiple specialized AI agents to provide comprehensive security analysis.
Modern AI architecture pattern where specialized agents collaborate on complex tasks.

Agents:
1. Vulnerability Analyzer Agent: Queries databases, correlates findings
2. Code Context Analyzer Agent: Analyzes code usage and reachability
3. Remediation Planner Agent: Generates migration strategies
4. Report Generator Agent: Creates human-readable reports

This demonstrates cutting-edge AI + Security fusion!
"""

import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from agent.config_loader import get_config


class AgentType(Enum):
    """Types of specialized agents"""
    VULNERABILITY_ANALYZER = "vulnerability_analyzer"
    CODE_CONTEXT_ANALYZER = "code_context_analyzer"
    REMEDIATION_PLANNER = "remediation_planner"
    REPORT_GENERATOR = "report_generator"


@dataclass
class AgentMessage:
    """Message passed between agents"""
    sender: AgentType
    receiver: AgentType
    message_type: str  # "query", "result", "request"
    payload: Dict[str, Any]
    metadata: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sender": self.sender.value,
            "receiver": self.receiver.value,
            "message_type": self.message_type,
            "payload": self.payload,
            "metadata": self.metadata or {}
        }


class BaseAgent:
    """Base class for all agents"""

    def __init__(self, agent_type: AgentType):
        self.agent_type = agent_type
        self.config = get_config()
        self.message_history: List[AgentMessage] = []

    def receive_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """
        Receive and process a message from another agent.

        Returns:
            Response message or None
        """
        self.message_history.append(message)
        return self.process_message(message)

    def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Override in subclasses"""
        raise NotImplementedError

    def send_message(self, receiver: AgentType, message_type: str, payload: Dict[str, Any]) -> AgentMessage:
        """Create a new message"""
        return AgentMessage(
            sender=self.agent_type,
            receiver=receiver,
            message_type=message_type,
            payload=payload
        )


class VulnerabilityAnalyzerAgent(BaseAgent):
    """
    Specializes in vulnerability detection and correlation.
    Queries multiple databases and deduplicates findings.
    """

    def __init__(self):
        super().__init__(AgentType.VULNERABILITY_ANALYZER)

    def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process vulnerability analysis requests"""

        if message.message_type == "analyze_component":
            component = message.payload.get("component")
            sources = message.payload.get("sources", ["osv", "github", "kev"])

            # Perform vulnerability scan
            vulnerabilities = self._scan_component(component, sources)

            return self.send_message(
                receiver=AgentType.CODE_CONTEXT_ANALYZER,
                message_type="vulnerabilities_found",
                payload={
                    "component": component,
                    "vulnerabilities": vulnerabilities,
                    "sources_queried": sources
                }
            )

        return None

    def _scan_component(self, component: Dict[str, Any], sources: List[str]) -> List[Dict[str, Any]]:
        """Scan component for vulnerabilities"""
        from agent.vulnerability_aggregator import aggregate_vulnerabilities

        package_name = component.get("name", "")
        version = component.get("version", "")
        ecosystem = self._detect_ecosystem(component)

        vulnerabilities = aggregate_vulnerabilities(
            package_name,
            version,
            ecosystem,
            sources
        )

        return vulnerabilities

    def _detect_ecosystem(self, component: Dict[str, Any]) -> str:
        """Detect package ecosystem from component"""
        purl = component.get("purl", "")
        if "npm" in purl:
            return "npm"
        elif "pypi" in purl:
            return "PyPI"
        elif "maven" in purl:
            return "Maven"
        return None


class CodeContextAnalyzerAgent(BaseAgent):
    """
    Specializes in code analysis and reachability detection.
    Determines if vulnerabilities are actually exploitable.
    """

    def __init__(self):
        super().__init__(AgentType.CODE_CONTEXT_ANALYZER)

    def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process code context analysis requests"""

        if message.message_type == "vulnerabilities_found":
            component = message.payload.get("component")
            vulnerabilities = message.payload.get("vulnerabilities")
            project_root = message.payload.get("project_root")

            # Analyze reachability
            context_analysis = self._analyze_code_context(component, project_root)

            # Enhance vulnerabilities with context
            enhanced_vulns = self._enhance_with_context(vulnerabilities, context_analysis)

            return self.send_message(
                receiver=AgentType.REMEDIATION_PLANNER,
                message_type="context_analyzed",
                payload={
                    "component": component,
                    "vulnerabilities": enhanced_vulns,
                    "code_context": context_analysis
                }
            )

        return None

    def _analyze_code_context(self, component: Dict[str, Any], project_root: Optional[str]) -> Dict[str, Any]:
        """Analyze how component is used in code"""

        if not project_root:
            return {"reachable": True, "confidence": "low", "reason": "No code analysis - assuming reachable"}

        from agent.reachability_analyzer import analyze_reachability

        # Perform reachability analysis
        reachability = analyze_reachability(
            component,
            sbom_data={},  # simplified
            project_root=project_root,
            enable_level_2=True
        )

        return reachability

    def _enhance_with_context(
        self,
        vulnerabilities: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Enhance vulnerabilities with context information"""

        enhanced = []
        for vuln in vulnerabilities:
            vuln_copy = vuln.copy()
            vuln_copy["reachability"] = context
            vuln_copy["reachability_score"] = self._calculate_score(context)
            enhanced.append(vuln_copy)

        return enhanced

    def _calculate_score(self, context: Dict[str, Any]) -> float:
        """Calculate reachability score"""
        if not context.get("reachable", True):
            return 0.0

        confidence = context.get("confidence", "medium")
        if confidence == "high":
            return 1.0
        elif confidence == "medium":
            return 0.7
        else:
            return 0.5


class RemediationPlannerAgent(BaseAgent):
    """
    Specializes in generating remediation strategies.
    Uses AI to create personalized migration guides.
    """

    def __init__(self):
        super().__init__(AgentType.REMEDIATION_PLANNER)

    def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process remediation planning requests"""

        if message.message_type == "context_analyzed":
            component = message.payload.get("component")
            vulnerabilities = message.payload.get("vulnerabilities")
            code_context = message.payload.get("code_context")
            project_root = message.payload.get("project_root")

            # Generate remediation plan
            remediation = self._generate_remediation_plan(
                component,
                vulnerabilities,
                code_context,
                project_root
            )

            return self.send_message(
                receiver=AgentType.REPORT_GENERATOR,
                message_type="remediation_ready",
                payload={
                    "component": component,
                    "vulnerabilities": vulnerabilities,
                    "remediation": remediation,
                    "code_context": code_context
                }
            )

        return None

    def _generate_remediation_plan(
        self,
        component: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        code_context: Dict[str, Any],
        project_root: Optional[str]
    ) -> Dict[str, Any]:
        """Generate AI-powered remediation plan"""

        # Use AI remediation advisor if available
        if self.config.is_ai_enabled():
            from agent.ai_remediation_advisor import get_ai_remediation_advice

            return get_ai_remediation_advice(
                component=component,
                vulnerabilities=vulnerabilities,
                project_root=project_root,
                reachability_analysis=code_context
            )
        else:
            # Fallback to basic remediation
            from agent.remediation_advisor import generate_remediation_advice
            return generate_remediation_advice(vulnerabilities)


class ReportGeneratorAgent(BaseAgent):
    """
    Specializes in generating comprehensive reports.
    Combines all agent findings into actionable documentation.
    """

    def __init__(self):
        super().__init__(AgentType.REPORT_GENERATOR)

    def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process report generation requests"""

        if message.message_type == "remediation_ready":
            report = self._generate_comprehensive_report(message.payload)

            return self.send_message(
                receiver=AgentType.VULNERABILITY_ANALYZER,  # Back to orchestrator
                message_type="analysis_complete",
                payload={"report": report}
            )

        return None

    def _generate_comprehensive_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate final comprehensive report"""

        component = data.get("component", {})
        vulnerabilities = data.get("vulnerabilities", [])
        remediation = data.get("remediation", {})
        code_context = data.get("code_context", {})

        # Calculate summary metrics
        total_vulns = len(vulnerabilities)
        reachable_vulns = sum(1 for v in vulnerabilities if v.get("reachability", {}).get("reachable", True))
        max_cvss = max([v.get("cvss", 0.0) for v in vulnerabilities], default=0.0)

        return {
            "component": component,
            "summary": {
                "total_vulnerabilities": total_vulns,
                "reachable_vulnerabilities": reachable_vulns,
                "max_cvss": max_cvss,
                "is_reachable": code_context.get("reachable", True),
                "confidence": code_context.get("confidence", "low")
            },
            "vulnerabilities": vulnerabilities,
            "remediation": remediation,
            "code_context": code_context,
            "generated_by": "PRISM Multi-Agent System"
        }


class MultiAgentOrchestrator:
    """
    Orchestrates multiple specialized agents to analyze vulnerabilities.
    Implements a collaborative AI architecture.
    """

    def __init__(self):
        self.config = get_config()
        self.enabled = self.config.is_multi_agent_enabled()

        # Initialize agents
        self.agents = {
            AgentType.VULNERABILITY_ANALYZER: VulnerabilityAnalyzerAgent(),
            AgentType.CODE_CONTEXT_ANALYZER: CodeContextAnalyzerAgent(),
            AgentType.REMEDIATION_PLANNER: RemediationPlannerAgent(),
            AgentType.REPORT_GENERATOR: ReportGeneratorAgent()
        }

        # Enabled agents from config
        self.enabled_agent_names = self.config.get_enabled_agents()

        # Message queue
        self.message_queue: List[AgentMessage] = []
        self.execution_log: List[Dict[str, Any]] = []

    def analyze_component(
        self,
        component: Dict[str, Any],
        project_root: Optional[str] = None,
        sources: List[str] = None
    ) -> Dict[str, Any]:
        """
        Orchestrate multi-agent analysis of a component.

        Args:
            component: SBOM component to analyze
            project_root: Project root directory for code analysis
            sources: Vulnerability sources to query

        Returns:
            Comprehensive analysis report from all agents
        """

        if not self.enabled:
            print("⚠️  Multi-agent system is disabled. Using single-agent analysis.")
            return self._fallback_single_agent_analysis(component, project_root, sources)

        print(f"🤖 Starting multi-agent analysis for {component.get('name')}...")

        # Step 1: Vulnerability Analyzer Agent
        print("   Agent 1: Vulnerability Analyzer - Scanning databases...")
        initial_message = AgentMessage(
            sender=AgentType.VULNERABILITY_ANALYZER,
            receiver=AgentType.VULNERABILITY_ANALYZER,
            message_type="analyze_component",
            payload={
                "component": component,
                "sources": sources or ["osv", "github", "kev"],
                "project_root": project_root
            }
        )

        # Process message through agent pipeline
        current_message = initial_message
        agent_sequence = [
            AgentType.VULNERABILITY_ANALYZER,
            AgentType.CODE_CONTEXT_ANALYZER,
            AgentType.REMEDIATION_PLANNER,
            AgentType.REPORT_GENERATOR
        ]

        for i, agent_type in enumerate(agent_sequence):
            if current_message is None:
                break

            agent = self.agents[agent_type]

            # Log execution
            self.execution_log.append({
                "step": i + 1,
                "agent": agent_type.value,
                "message_type": current_message.message_type,
                "timestamp": self._get_timestamp()
            })

            # Process message
            response = agent.receive_message(current_message)

            if response:
                # Update message payload with project_root for next agent
                if project_root and "project_root" not in response.payload:
                    response.payload["project_root"] = project_root

                current_message = response
            else:
                current_message = None

        # Extract final report
        if current_message and current_message.message_type == "analysis_complete":
            report = current_message.payload.get("report", {})
            report["execution_log"] = self.execution_log

            print(f"✅ Multi-agent analysis complete! {len(self.execution_log)} steps executed.")
            return report
        else:
            print("⚠️  Multi-agent analysis incomplete.")
            return {"error": "Analysis incomplete", "execution_log": self.execution_log}

    def _fallback_single_agent_analysis(
        self,
        component: Dict[str, Any],
        project_root: Optional[str],
        sources: List[str]
    ) -> Dict[str, Any]:
        """Fallback to single-agent analysis if multi-agent disabled"""

        # Simple sequential analysis
        vuln_agent = self.agents[AgentType.VULNERABILITY_ANALYZER]
        vulnerabilities = vuln_agent._scan_component(component, sources or ["osv"])

        return {
            "component": component,
            "vulnerabilities": vulnerabilities,
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "max_cvss": max([v.get("cvss", 0.0) for v in vulnerabilities], default=0.0)
            },
            "mode": "single-agent (fallback)"
        }

    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()

    def get_execution_log(self) -> List[Dict[str, Any]]:
        """Get execution log for debugging/visualization"""
        return self.execution_log

    def reset(self):
        """Reset orchestrator state"""
        self.message_queue.clear()
        self.execution_log.clear()
        for agent in self.agents.values():
            agent.message_history.clear()


# Convenience function
def analyze_with_agents(
    component: Dict[str, Any],
    project_root: Optional[str] = None,
    sources: List[str] = None
) -> Dict[str, Any]:
    """
    Quick function to run multi-agent analysis.

    Example:
        result = analyze_with_agents(
            component={"name": "lodash", "version": "4.17.20"},
            project_root="/path/to/project"
        )
    """
    orchestrator = MultiAgentOrchestrator()
    return orchestrator.analyze_component(component, project_root, sources)


if __name__ == "__main__":
    # Test multi-agent system
    print("=== PRISM Multi-Agent System Test ===\n")

    orchestrator = MultiAgentOrchestrator()
    print(f"Multi-Agent Enabled: {orchestrator.enabled}")
    print(f"Enabled Agents: {', '.join(orchestrator.enabled_agent_names)}")
    print(f"Total Agents: {len(orchestrator.agents)}")

    print("\n✅ Multi-agent orchestrator initialized!")
    print("\nAgent Pipeline:")
    for i, agent_type in enumerate(orchestrator.agents.keys(), 1):
        print(f"  {i}. {agent_type.value}")
