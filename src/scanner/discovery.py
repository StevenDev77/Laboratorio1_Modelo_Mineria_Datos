"""
Módulo de Descubrimiento Automático de Microservicios y Archivos
Identifica la estructura de directorios, microservicios, tecnologías y archivos a analizar.
"""

import os
from typing import Dict, List, Any

SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".properties": "properties"
}

SUPPORTED_FILENAMES = {
    "dockerfile": "dockerfile",
    "docker-compose.yml": "yaml",
    "docker-compose.yaml": "yaml"
}

SERVICE_INDICATORS = {
    "package.json": "Node.js / Express / NestJS",
    "requirements.txt": "Python / FastAPI / Flask",
    "pom.xml": "Java / Spring Boot (Maven)",
    "build.gradle": "Java / Spring Boot (Gradle)",
    "Dockerfile": "Containerized Service",
    "application.yml": "Spring Boot / Microservice Config",
    "application.properties": "Spring Boot / Microservice Config"
}

def discover_project_structure(root_path: str) -> Dict[str, Any]:
    root_path = os.path.abspath(root_path)
    project_name = os.path.basename(root_path)

    microservices = {}
    all_files = []

    # 1. Buscar microservicios en subdirectorios directos o de nivel 2
    for entry in os.scandir(root_path):
        if entry.is_dir() and not entry.name.startswith(('.', '__', 'node_modules', 'venv', 'target', 'dist', 'reports')):
            service_path = entry.path
            service_name = entry.name
            techs = []

            for ind_file, tech_name in SERVICE_INDICATORS.items():
                if os.path.exists(os.path.join(service_path, ind_file)):
                    techs.append(tech_name)

            if techs:
                microservices[service_name] = {
                    "path": service_path,
                    "technologies": list(set(techs)),
                    "files": []
                }

    # Si no se identificaron subcarpetas de servicios, tratar la raíz como un microservicio único
    if not microservices:
        microservices[project_name] = {
            "path": root_path,
            "technologies": ["Generic Microservice / Monorepo"],
            "files": []
        }

    # 2. Recorrer y asociar archivos a cada microservicio o a nivel de infraestructura
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Ignorar directorios no relevantes
        dirnames[:] = [d for d in dirnames if d not in {
            'node_modules', 'venv', '.git', '__pycache__', 'target', 'build', '.idea', '.vscode', 'reports', 'dist'
        }]

        for f in filenames:
            ext = os.path.splitext(f)[1].lower()
            fname_lower = f.lower()

            is_supported = ext in SUPPORTED_EXTENSIONS or fname_lower in SUPPORTED_FILENAMES or fname_lower.startswith("dockerfile")

            if is_supported:
                full_path = os.path.join(dirpath, f)
                rel_path = os.path.relpath(full_path, root_path)

                # Identificar a qué microservicio pertenece
                assigned_service = "infrastructure"
                for s_name, s_info in microservices.items():
                    try:
                        common = os.path.commonpath([s_info["path"], full_path])
                        if common == s_info["path"]:
                            assigned_service = s_name
                            break
                    except ValueError:
                        pass

                file_info = {
                    "name": f,
                    "relative_path": rel_path.replace("\\", "/"),
                    "absolute_path": full_path,
                    "service": assigned_service,
                    "extension": ext or fname_lower
                }
                all_files.append(file_info)
                if assigned_service in microservices:
                    microservices[assigned_service]["files"].append(file_info)

    return {
        "project_name": project_name,
        "root_path": root_path,
        "microservices": microservices,
        "analyzable_files": all_files,
        "total_files": len(all_files),
        "total_services": len(microservices)
    }
