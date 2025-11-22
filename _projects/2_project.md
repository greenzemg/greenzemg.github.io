---
layout: page
title: Digital Twin Integration for Smart Manufacturing
description: A comprehensive Digital Twin for a Festo manufacturing factory setup used by Cordis
img: assets/img/digital-twin/dt-architecture.png
importance: 2
category: work
github: # Internal project
related_publications:
tags:
    [
        Unity 3D,
        C#,
        WebSocket,
        OPC UA,
        Docker,
        Scrum,
        Digital Twin,
        Smart Manufacturing,
    ]
---

This project was executed in collaboration with the Digital Twin Lab (DT Lab) at Eindhoven University of Technology (TU/e) and the High-Tech Software Cluster (HTSC) at the Brainport Industries Campus (BIC). The primary objective was to design and implement a comprehensive Digital Twin (DT) for a Festo manufacturing factory setup used by Cordis, a model-based software generation company. This initiative served as the inaugural industrial trial of the DT Lab's open-source architecture, bridging the gap between academic research and practical industrial application.

#### Problem & Challenges

In high-tech manufacturing, validating control software on physical machinery is costly, risky, and time-consuming. Errors can lead to hardware damage or significant downtime. Cordis needed a virtual environment to safely test their PLC (Programmable Logic Controller) control software before deployment.

Key challenges included:

-   **Real-Time Latency**: Strict adherence to real-time constraints (latency under 300ms) for accurate mirroring.
-   **Architectural Scalability**: Modular design to accommodate future extensions.
-   **Data Integrity & Integration**: Seamless integration of heterogeneous systems (PLCs, Unity, external estimators).
-   **Legacy constraints**: Replicating specific behavior of the Festo educational manufacturing system.

<!-- Image of Digital Twin Setup -->
<div class="row">
    <div class="col-sm-8 col-md-6 mx-auto mt-3 mt-md-0">
        {% include figure.html path="assets/img/digital-twin/festo-setup.png" title="Festo Manufacturing Factory Setup" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

#### Solution

To address these challenges, we engineered a modular, event-driven solution utilizing the ISO 42010 standard for system architecture.

##### Architecture

The system is built on a decoupled, layered architecture to ensure flexibility and maintainability:

-   **I/O Switch & Virtual Gateway**: Acting as the central nervous system, routing data between physical/simulated factory and visualization layer.
-   **Factory State Estimator**: Maintains the "truth" of the factory's state independent of visualization.
-   **Simulated Factory**: Tree-structured simulation engine mimicking independent operation of real-world PLCs.
-   **Unity Visualizer**: Purely presentational layer in Unity (C#) rendering state in 3D.

<div class="row justify-content-sm-center">
  <div class="col-sm-12 mt-3 mt-md-0">
    {% include figure.html path="assets/img/digital-twin/dt-architecture.png" title="Digital Twin Architecture" class="img-fluid rounded z-depth-1" %}
  </div>
</div>

##### Tools & Technology Stack

-   **Core Platform**: Unity 3D for real-time visualization and simulation.
-   **Communication**: WebSocket and OPC UA protocols.
-   **Project Management**: JIRA, GitLab.
-   **Containerization**: Docker.

#### My Role & Contributions

This project was a collaborative effort involving a multidisciplinary team of eight engineers. My contribution was twofold:

##### Scrum Master

I led the agile execution of the project, focusing on efficient task management and smooth team collaboration. I managed sprint ceremonies, removed impediments, and optimized processes using tools like Miro, JIRA, and MS Teams.

##### Core Developer: I/O Switch Implementation

I took full ownership of the I/O Switch, a critical architectural component acting as the central router for the system.

-   **Functionality**: Designed routing logic for data flow between physical world and digital model.
-   **Data Integrity**: Implemented strict JSON-based message validation.
-   **Mode Switching**: Engineered logic for instant toggling between "Physical Mode" and "Simulation Mode".

#### Result

The project successfully delivered a functioning Digital Twin of the Festo factory setup.

Key Outcomes:

-   **Closed-Loop Validation**: Enabled safe virtual validation of control software.
-   **Real-Time Performance**: Achieved required latency for effective monitoring.
-   **Foundation for R&D**: Established a robust architectural baseline for future research.
-   **Educational Impact**: System used to demonstrate digital twin capabilities at Brainport Industries Campus.
