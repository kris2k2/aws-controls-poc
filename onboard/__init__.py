"""AWS service onboarding tool.

Takes one AWS service, assesses it from its API contract alone, and produces a
control set rendered as generic artifacts. The pipeline runs six stages in
order (Resolve, Assess, Select, Generate, Compose, Validate); each stage writes
a structured, versioned file that the next stage reads.
"""

__version__ = "0.1.0"
