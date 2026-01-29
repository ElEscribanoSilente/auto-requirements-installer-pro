# Auto Requirements Installer Pro

**Versión:** 2.0.0  
**Autor:** Esraderey  
**Coautor:** Escribano Silente

---

## Descripción

Herramienta avanzada con interfaz gráfica (GUI) para la gestión automática de dependencias en proyectos Python. Escanea código fuente, detecta imports, identifica dependencias faltantes y facilita su instalación de forma automatizada.

---

## Características Principales

### Escaneo y Análisis
- **Análisis AST (Abstract Syntax Tree):** Escaneo profundo de imports usando el módulo `ast` de Python para máxima precisión
- **Detección completa de stdlib:** Soporte para Python 3.8 hasta 3.12+
- **Mapeo extensivo import→PyPI:** Más de 250 paquetes mapeados con nombres correctos de PyPI
- **Escaneo recursivo de directorios:** Con exclusión automática de directorios comunes (venv, __pycache__, node_modules, etc.)
- **Localización de imports:** Rastrea en qué archivos se usa cada dependencia

### Gestión de Paquetes
- **Instalación automatizada:** Instala paquetes faltantes directamente desde la interfaz
- **Actualización de paquetes:** Detecta y actualiza paquetes desactualizados
- **Desinstalación segura:** Elimina paquetes con confirmación
- **Freeze de dependencias:** Genera listado completo de paquetes instalados con versiones

### Entornos Virtuales
- **Creación de venvs:** Crea entornos virtuales desde la interfaz
- **Detección automática:** Identifica entornos virtuales existentes en el proyecto
- **Selector de intérprete:** Permite elegir qué instalación de Python usar

### Exportación
- **requirements.txt:** Formato estándar de pip
- **Pipfile:** Formato de Pipenv
- **pyproject.toml:** Formato PEP 517/518
- **Poetry:** Formato específico de Poetry

### Seguridad
- **Verificación de vulnerabilidades:** Consulta la base de datos de PyPI Safety para detectar paquetes vulnerables
- **Indicadores visuales:** Marca paquetes con vulnerabilidades conocidas

### Interfaz de Usuario
- **Tema oscuro/claro:** Soporte para ambos modos de visualización
- **Log en tiempo real:** Registro detallado de todas las operaciones
- **Barra de progreso:** Indicadores visuales durante operaciones largas
- **Historial persistente:** Base de datos SQLite con registro de operaciones y escaneos

### Rendimiento
- **Caché de paquetes:** Almacena información de PyPI para consultas más rápidas (expiración: 24 horas)
- **Ejecución concurrente:** Uso de ThreadPoolExecutor para operaciones paralelas

---

## Requisitos del Sistema

- **Python:** 3.8 o superior
- **Sistema Operativo:** Windows, macOS, Linux
- **Dependencias:** 
  - `tkinter` (incluido en Python estándar)
  - `toml` (se instala automáticamente si no está presente)

---

## Instalación

```bash
# Clonar o descargar el archivo
# No requiere instalación adicional

# Ejecutar directamente
python auto-requirements-installer-pro.py
```

---

## Uso

### Inicio Rápido

1. Ejecutar el script
2. Seleccionar la carpeta del proyecto usando "Explorar"
3. Hacer clic en "Escanear Proyecto"
4. Revisar los imports detectados en la tabla
5. Seleccionar los paquetes faltantes e instalarlos

### Pestañas de la Interfaz

| Pestaña | Función |
|---------|---------|
| **Escaneo** | Análisis de imports del proyecto |
| **Paquetes Instalados** | Gestión de paquetes del entorno actual |
| **Entorno Virtual** | Creación y gestión de venvs |
| **Exportar** | Generación de archivos de dependencias |
| **Historial** | Registro de operaciones realizadas |
| **Configuración** | Ajustes de la aplicación |

### Estados de Paquetes

| Estado | Descripción |
|--------|-------------|
| `stdlib` | Módulo de la biblioteca estándar de Python |
| `installed` | Paquete instalado en el entorno |
| `missing` | Paquete no instalado (requiere instalación) |
| `unknown` | No se pudo determinar el estado |
| `error` | Error al verificar el paquete |

---

## Estructura de Archivos

```
~/.requirements_installer_pro/
├── package_cache.json    # Caché de información de PyPI
├── history.db            # Base de datos SQLite de historial
└── settings.json         # Configuración de la aplicación
```

---

## Mapeo de Imports

La herramienta incluye mapeo para categorías como:

- **Machine Learning/AI:** sklearn→scikit-learn, torch→torch, transformers, etc.
- **Data Science:** numpy, pandas, scipy, statsmodels
- **Visualización:** matplotlib, seaborn, plotly, bokeh, streamlit
- **Web Frameworks:** flask→Flask, django→Django, fastapi, etc.
- **Bases de Datos:** sqlalchemy→SQLAlchemy, pymongo, redis, etc.
- **Computer Vision:** cv2→opencv-python, skimage→scikit-image
- **NLP:** nltk, spacy, transformers, gensim
- **CLI:** click, typer, rich, tqdm
- **Testing:** pytest, hypothesis, coverage
- **Cloud/DevOps:** boto3, docker, kubernetes
- Y más de 200 mapeos adicionales

---

## API de Clases Principales

### ImportScanner
```python
scanner = ImportScanner()
scanner.scan_directory(Path("/ruta/proyecto"))
third_party = scanner.get_third_party_imports()
```

### PackageInstaller
```python
installer = PackageInstaller(python_path)
success, output = installer.install("requests")
```

### VulnerabilityChecker
```python
checker = VulnerabilityChecker()
checker.load_database()
vulns = checker.check_package("requests", "2.25.0")
```

### RequirementsExporter
```python
content = RequirementsExporter.to_requirements_txt(packages)
content = RequirementsExporter.to_pyproject_toml(packages, "mi-proyecto")
```

---

## Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue o pull request en el repositorio.

---

## Licencia

```
Creative Commons Attribution 4.0 International (CC BY 4.0)

Copyright (c) 2024 Esraderey & Escribano Silente

Se permite:
- Compartir: copiar y redistribuir el material en cualquier medio o formato
- Adaptar: remezclar, transformar y construir sobre el material para cualquier 
  propósito, incluso comercialmente

Bajo los siguientes términos:
- Atribución: Debe dar crédito apropiado a los autores originales 
  (Esraderey y Escribano Silente), proporcionar un enlace a la licencia e 
  indicar si se realizaron cambios. Puede hacerlo de cualquier manera razonable, 
  pero no de forma que sugiera que los licenciantes respaldan su uso.

Sin restricciones adicionales: No puede aplicar términos legales o medidas 
tecnológicas que restrinjan legalmente a otros de hacer cualquier cosa que 
la licencia permita.

https://creativecommons.org/licenses/by/4.0/
```

---

## Historial de Versiones

### v2.0.0
- Interfaz gráfica completa con tkinter
- Sistema de caché para consultas PyPI
- Verificación de vulnerabilidades de seguridad
- Soporte para múltiples formatos de exportación
- Gestión de entornos virtuales integrada
- Historial persistente con SQLite
- Tema oscuro/claro
- Mapeo extensivo de más de 250 paquetes

---

## Contacto

**Autor:** Esraderey  
**Coautor:** Escribano Silente
