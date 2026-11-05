"""
Module: run_agent.py
Description: Production-ready enterprise component for Run Agent.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import logging
from dotenv import load_dotenv
load_dotenv()  # Zero Trust env loading

import logging


logger = logging.getLogger(__name__)
"""
Module: run_agent.py
Description: Production-ready enterprise component for Run Agent.
Hardened with Zero Trust, structured logging, and dynamic environment configuration.
"""

import os
import sys
from dotenv import load_dotenv

# Ensure package path is accessible
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Load environment variables (OPENAI_API_KEY) before importing LangChain models
load_dotenv()

from src.agent.compliance_agent import app
from langchain_core.messages import HumanMessage

def print_stream(stream):
    """Utility to print the stream from LangGraph."""
    for s in stream:
        # En stream_mode="values", s es el diccionario completo de AgentState
        message = s["messages"][-1]
        if hasattr(message, "tool_calls") and message.tool_calls:
            logger.info(f"\n[Agent is thinking...] Calling tool(s): {', '.join([tc['name'] for tc in message.tool_calls])}")
        elif message.content:
            logger.info(f"\n[Agent]: {message.content}")

def main():
    logger.info("=" * 80)
    logger.info(" IT_COMPLIANCE_MANAGER — LANGGRAPH AGENT TERMINAL")
    logger.info("=" * 80)
    logger.info(" Escribe tu comando de auditoría o 'salir' para terminar.")
    logger.info(" Ejemplo: 'Haz una auditoría DORA para AcmeCorp en ./data'")
    logger.info("-" * 80)
    
    # Check if OPENAI_API_KEY is set
    if not os.environ.get("OPENAI_API_KEY"):
        logger.info("\n[!] ADVERTENCIA: La variable de entorno OPENAI_API_KEY no está configurada.")
        logger.info("[!] El agente de LangGraph (usando OpenAI) fallará si no configuras esta clave.")
        logger.info("[!] Por favor, configura tu API key antes de continuar.\n")
    
    while True:
        try:
            user_input = input("\n[Usuario] > ")
            if user_input.lower() in ["salir", "exit", "quit"]:
                logger.info("Saliendo...")
                break
                
            if not user_input.strip():
                continue
                
            logger.info("\n[Agent is processing...]")
            inputs = {"messages": [HumanMessage(content=user_input)]}
            
            # Run the agent workflow
            print_stream(app.stream(inputs, stream_mode="values"))
            
        except KeyboardInterrupt:
            logger.info("\nSaliendo...")
            break
        except Exception as e:
            logger.info(f"\n[!] Ocurrió un error: {e}")

if __name__ == "__main__":
    main()
