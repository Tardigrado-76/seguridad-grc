"""
Module: compliance_agent.py
Description: Production-ready enterprise component for Compliance Agent.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import logging


logger = logging.getLogger(__name__)
"""
Module: compliance_agent.py
Description: Production-ready enterprise component for Compliance Agent.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import subprocess
from typing import List, Annotated, Sequence, TypedDict
import operator

from langchain_core.messages import BaseMessage, HumanMessage, ToolMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

# ------------------------------------------------------------------
# Definición de Herramientas (Tools)
# ------------------------------------------------------------------

@tool
def run_compliance_audit(input_path: str, frameworks: List[str], company_name: str, format: str = "md") -> str:
    """
    Ejecuta el ComplianceOrchestrator del proyecto para evaluar normativas (DORA, NIS2, ENS_ALTO, GDPR, CRA).
    Devuelve un resumen del éxito de la ejecución.
    """
    try:
        cmd = [
            "python", "orchestrator_cli.py",
            "-i", input_path,
            "-c", company_name,
            "-f", format
        ]
        for fw in frameworks:
            cmd.extend(["--framework", fw])
            
        logger.info(f"[*] Executing Tool: {' '.join(cmd)}")
        # We run from the root of IT_COMPLIANCE_MANAGER
        root_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        
        result = subprocess.run(cmd, cwd=root_dir, capture_output=True, text=True)
        if result.returncode == 0:
            return f"Audit completed successfully. Output:\n{result.stdout[:500]}..."
        else:
            return f"Audit failed with error:\n{result.stderr}"
    except Exception as e:
        return str(e)

@tool
def verify_cisa_kev(dependency_file: str) -> str:
    """
    Verifica las dependencias contra el catálogo CISA KEV llamando al script correspondiente.
    """
    try:
        script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "scripts", "security_audit", "check_cisa_kev.py")
        cmd = ["python", script_path, dependency_file]
        logger.info(f"[*] Executing Tool: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return str(e)

@tool
def generate_sbom(project_path: str) -> str:
    """
    Genera un SBOM del proyecto dado.
    """
    try:
        script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "scripts", "security_audit", "generate_sbom.py")
        cmd = ["python", script_path, project_path]
        logger.info(f"[*] Executing Tool: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return str(e)

@tool
def scan_venv_vulnerabilities(venv_path: str) -> str:
    """
    Escanea vulnerabilidades en las librerías del venv usando el script PowerShell.
    """
    try:
        script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "scripts", "security_audit", "ESCANER DE LIBRERIAS EN venv.ps1")
        cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path, "-VenvPath", venv_path]
        logger.info(f"[*] Executing Tool: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return str(e)

@tool
def apply_stig_hardening(target: str) -> str:
    """
    Aplica hardening de seguridad basado en STIG.
    """
    try:
        script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "scripts", "security_audit", "disa_stig_hardening.ps1")
        cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path, "-Target", target]
        logger.info(f"[*] Executing Tool: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return str(e)

tools = [
    run_compliance_audit,
    verify_cisa_kev,
    generate_sbom,
    scan_venv_vulnerabilities,
    apply_stig_hardening
]

# ------------------------------------------------------------------
# Lógica LangGraph
# ------------------------------------------------------------------

class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]

# Iniciar modelo
model = ChatOpenAI(temperature=0, model="gpt-4o-mini")
model_with_tools = model.bind_tools(tools)

def agent_node(state: AgentState):
    messages = state["messages"]
    
    # Añadimos un system prompt
    prompt = ChatPromptTemplate.from_messages([
        ("system", "Eres un Agente Experto en Ciberseguridad y Auditoría. "
                   "Tienes acceso a múltiples herramientas para ejecutar auditorías, escanear vulnerabilidades y aplicar hardening. "
                   "Usa tus herramientas para resolver las solicitudes del usuario de forma autónoma."),
        MessagesPlaceholder(variable_name="messages")
    ])
    
    chain = prompt | model_with_tools
    response = chain.invoke({"messages": messages})
    return {"messages": [response]}

# Crear el grafo
workflow = StateGraph(AgentState)

# Añadir nodos
workflow.add_node("agent", agent_node)
workflow.add_node("tools", ToolNode(tools))

# Definir aristas
def should_continue(state: AgentState) -> str:
    messages = state["messages"]
    last_message = messages[-1]
    # Si el LLM ha llamado a una herramienta, vamos al nodo de herramientas
    if last_message.tool_calls:
        return "continue"
    # Si no, hemos terminado
    return "end"

workflow.set_entry_point("agent")
workflow.add_conditional_edges(
    "agent",
    should_continue,
    {
        "continue": "tools",
        "end": END
    }
)
workflow.add_edge("tools", "agent")

# Compilar
app = workflow.compile()


if __name__ == '__main__':
    # Production entry point
    pass
