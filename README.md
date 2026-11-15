# Threat Hunting Labs

Notas de los labs de threat hunting que voy resolviendo, sobre todo en [CyberDefenders](https://cyberdefenders.org/). Soy analista de CTI y uso este repositorio como cuaderno de aprendizaje y portfolio.

Cada lab tiene su propia carpeta con una nota en Markdown y sus capturas. Todas las notas siguen la misma estructura:

1. **Contexto:** el escenario.
2. **Preguntas del lab:** qué busco, la consulta que uso, el resultado y por qué esa es la respuesta.
3. **Cierre:** cadena del ataque, TTPs de MITRE ATT&CK e IOCs.


## Labs

| Lab | Plataforma | Técnicas ATT&CK | Herramientas | Nota |
| --- | --- | --- | --- | --- |
| T1110-003: password spraying por RDP | CyberDefenders | T1110.003, T1078, T1021.001 | Splunk | [Ver nota](T1110-003/T1110-003%20Lab.md) |
| REvil - GOLD SOUTHFIELD: ransomware REvil | CyberDefenders | T1486, T1490, T1059.001, T1027.010 | Splunk, Sysmon, CyberChef, ANY.RUN, VirusTotal | [Ver nota](REvil%20-%20GOLD%20SOUTHFIELD%20Lab/REvil%20-%20GOLD%20SOUTHFIELD%20Lab.md) |
| NerisBot: descargas maliciosas desde un servidor C2 | CyberDefenders | T1105, T1036.008 | Splunk, Suricata, Zeek, VirusTotal | [Ver nota](NerisBot%20Lab/NerisBot%20Lab.md) |
| Poisoned PyTorch: dependencia de Python envenenada que acaba en ransomware Lynx | CyberDefenders | T1195.001, T1059.001, T1552.001, T1021.001, T1136.002, T1490, T1486 | Splunk, Sysmon, CyberChef, VirusTotal | [Ver nota](Poisoned%20PyTorch%20Lab/Poisoned%20PyTorch%20Lab.md) |

## Estructura del repositorio

```
README.md
plantillas/
  Plantilla - Lab.md     plantilla que uso para cada lab nuevo
T1110-003/
  T1110-003 Lab.md       nota del lab
  img/                   capturas de la nota
REvil - GOLD SOUTHFIELD Lab/
  REvil - GOLD SOUTHFIELD Lab.md
  img/
NerisBot Lab/
  NerisBot Lab.md
  img/
Poisoned PyTorch Lab/
  Poisoned PyTorch Lab.md
  img/
```

Las notas están escritas en [Obsidian](https://obsidian.md/).
