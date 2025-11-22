---
layout: page
title: 2Mtest - Legacy Test Migration at ASML
description: A semi-automatic tool for migrating legacy test cases to modern testing framework (MTEST)
img: assets/img/2mtest/2mtest_arch.png
importance: 1
category: work
github: # Internal ASML project - not publicly available
related_publications:
tags:
    [
        Python,
        C/C++,
        Neo4j,
        Clang,
        Domain Specific Language,
        Lark,
        Jinja2,
        Docker,
        Linux,
    ]
---

As part of my Engineering Doctorate (EngD) final project at ASML, I tackled a common challenge faced by many large tech companies: migrating thousands of legacy test cases to a modern testing framework. Here's how I built a semi-automatic tool to transform legacy Python tests into ASML's new MTEST framework. In this context, semi-automatic means the tool does most of the work automatically but still needs a human to check and make sure the results are correct.

#### Problem

ASML's TWINSCAN lithography machines rely on a massive software stack that contain over 60 million lines of code developed over 40 years. Traditionaly, testing required initializing the entire system just to test a single component, leading to excessive CPU usage and slow test cycles. While ASML's new MTEST framework enables isolated module testing, migrating existing tests manually was time consuming taking engineers over 5 hours per test case, error prone and costly.

<!-- Image of Twin scan -->
<div class="row">
    <div class="col-sm-8 col-md-6 mx-auto mt-3 mt-md-0">
        {% include figure.html path="assets/img/2mtest/asml_twinscan.png" title="ASML TWINSCAN Lithography Machine" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

#### Solution: A Three-Stage Pipeline

To tackle the problem mentioned earlier, I designed and developed a semi-automatic migration tool consisting of three core components that work together in sequence. The figure below shows the overall architecture of the migration pipeline.

<div class="row justify-content-sm-center">
  <div class="col-sm-12 mt-3 mt-md-0">
    {% include figure.html path="assets/img/2mtest/2Mtest_pipeline.jpg" title="example image" class="img-fluid rounded z-depth-1" %}
  </div>
</div>

##### 1. Scanner - Building the Knowledge Graph

The Scanner is the first component in the migration pipeline, responsible for processing large-scale ASML C/C++ codebases to extract dependency graph at the function level and store it in Neo4j graph database. This graph data serves as a single source of truth to be queried later by the Analyzer to understand the dependencies accross components.

Neo4j is a graph database that stores information as nodes and relationships unlinke relational databases that store data in tabular form. Using Neo4j, it is easier to model and query connected data in a way that feels closer to how things relate in the real world. Unlike relational databases that depend on joins, Neo4j uses index-free adjacency, meaning each node directly “knows” its connected nodes without needing a global index lookup. This allows extremely fast traversal through large networks and makes Neo4j very efficient when working with highly connected data like call graphs in a complex source code base.

##### 2. Analyzer - Understanding Test Intent

The Analyzer takes inconsistent legacy Python tests and figures out what they're actually testing. Using a backtracking algorithm, it:

-   Starts from assertion statements and traces backward to find the System Under Test (SUT)
-   Identifies test inputs by analyzing function arguments
-   Extracts expected outputs from assertion comparisons
-   Partitions test code into Given-When-Then structure

The output is GTSL (Generic Test Specification Language), a domain-specific language I created as an intermediate representation. Think of it as a structured, human-readable format that captures the essence of any test regardless of the original language.

```python
# Example GTSL Output
IMPORTS
    MOKA
    LITXCAT
    ERROR
END

GLOBALS
    ZIMA_READ_PARAMS: hex = 0x2323
END

SUITE ZIMA_RDT_testcase
    DESCRIPTION "Testcase for the ZIMA reader interface"

    SETUP
        call obj_per1_inst.terminate()
        set self._pipipos_per1 = call PIPI.PIPIPOS(obj_per1)
    END
    CASE test_case_1
        DESCRIPTION "Test case 1 for ZIMA reader interface"
        INPUT
            in reader_elem: any
            in flag: bool
            in scramble: bool
        END
        OUTPUT
            out expected_out_1: float
            out expected_out_2: bool
        END
        GIVEN
            call obj_per1_inst.initialize()
            set flag = 'FALSE'
            set reader_elem = call self._populate_pos_param(8995, 'ZIMA_READ_PARAMS')
            set scramble = False
        END
        WHEN
            set reading_time = call immisc_per1.check_reading_time(reader_elem, flag, scramble)
        END
        THEN
            call self.assertEqual(reading_time, 0.9)
            call self.assertTrue(reader_elem.is_valid())
        END
    END
END
```

##### 3. Transpiler - Code Generation and Environment Setup
The Transpiler component converts (transforms) the abstract GTSL representation, produced by the Analyzer, into target Python test code that is compatible with the MTEST framework. In addition, this component is responsible for generating various configuration files required to run the test code on ASML's testing environment. To achieve this, the Transpiler's design follows three typical stages borrowed from compiler design.

#### Key Design Decisions

##### GTSL as Intermediate Language
Rather than going directly from Python to Python, we introduced **GTSL as a bridge**. This allows engineers to review and manually correct the analysis before final code generation.

##### Modular Architecture

Each component has a single responsibility and communicates through well-defined interfaces. This makes the tool extensible for future needs, like supporting C/C++ test migration or replacing the analyzer component with LLM.

<div class="row">
    <div class="col-sm mt-3 mt-md-0">
        {% include figure.html path="assets/img/2mtest/2mtest_arch.png" title="Migration Pipeline Architecture" class="img-fluid rounded z-depth-1" %}
    </div>
</div>

##### Dependency Graph First

By pre-computing the entire codebase's dependency graph, we can instantly answer complex questions like "what components does this function depend on?" without expensive runtime analysis.

#### Results and Impact
<!-- The semi-automatic migration tool we developed significantly improves efficiency by migrating test files in under five seconds compared to hours of manual effort. Beyond migration, the tool's scanner builds a detailed function-level dependency graph stored in Neo4j for other use cases such as detecting spaghetti code, identifying dead code, and performing impact and risk analysis. -->

Based on the project's results, the following claims can be made. First, the project demonstrates that the migration process, which previously required several hours of manual effort and the creation of more than seven separate files, can now be completed in less than five seconds. The tool automates the generation of all required files for MTEST-based test cases, thereby solving the inefficiency of manual migration. Second, the project shows that the dependency graph of the production code not only captures function-level relationships between components but can also be used for other use cases, including risk analysis, detection of dead code, and code refactoring. Third, the tool is not limited to migrating legacy test cases; it can also be used to create new MTEST-based test cases from scratch, thereby extending its utility beyond migration alone.


---
<!-- 
_This project was developed during my 10-month internship at ASML, working with senior engineers on critical testing infrastructure that supports the manufacturing of advanced semiconductor lithography systems._ -->
