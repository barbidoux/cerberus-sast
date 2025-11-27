"""
Program Slicer for Phase III Detection.

Extracts minimal code context (program slices) from data flows.
Achieves ~90% code reduction while preserving vulnerability context.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from cerberus.detection.flow_analyzer import DataFlow
from cerberus.detection.joern_client import JoernClient, JoernConfig
from cerberus.models.base import CodeLocation
from cerberus.models.finding import ProgramSlice, SliceLine


@dataclass
class SlicerConfig:
    """Configuration for program slicing."""

    include_control_structures: bool = True
    include_variable_definitions: bool = True
    context_lines: int = 2  # Lines before/after trace points
    max_slice_lines: int = 100
    parallel_extraction: bool = True
    max_concurrent: int = 5


@dataclass
class SliceResult:
    """Result from slicing a single data flow."""

    flow: DataFlow
    slice: Optional[ProgramSlice]
    success: bool
    error: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ProgramSlicer:
    """Extracts minimal code context from data flows.

    Uses Joern to perform backward and forward slicing from
    the trace points to extract only relevant code.
    """

    def __init__(
        self,
        config: Optional[SlicerConfig] = None,
        joern_client: Optional[JoernClient] = None,
    ) -> None:
        """Initialize program slicer.

        Args:
            config: Slicer configuration.
            joern_client: Joern client for CPG queries.
        """
        self.config = config or SlicerConfig()
        self.joern_client = joern_client or JoernClient()

    async def extract_slice(self, flow: DataFlow) -> SliceResult:
        """Extract program slice for a data flow.

        Args:
            flow: Data flow to slice.

        Returns:
            SliceResult with extracted slice or error.
        """
        try:
            # Get trace-relevant lines from Joern
            slice_data = await self.joern_client.get_slice(
                source_line=flow.source_location.line,
                sink_line=flow.sink_location.line,
                file_path=str(flow.source_location.file_path),
            )

            # Get trace line numbers from the flow
            trace_line_numbers = {
                step.location.line for step in flow.trace_steps
            }
            trace_line_numbers.add(flow.source_location.line)
            trace_line_numbers.add(flow.sink_location.line)

            # Convert to SliceLines
            slice_lines = self._convert_to_slice_lines(
                slice_data,
                trace_line_numbers,
                flow.source_location.line,
                flow.sink_location.line,
            )

            # Apply max lines limit
            if len(slice_lines) > self.config.max_slice_lines:
                slice_lines = self._prioritize_lines(
                    slice_lines,
                    trace_line_numbers,
                    self.config.max_slice_lines,
                )

            # Get control structures if configured
            control_structures = []
            if self.config.include_control_structures:
                control_structures = await self._get_control_structures(flow)

            # Get variable definitions if configured
            variable_definitions = []
            if self.config.include_variable_definitions:
                variable_definitions = await self._get_variable_definitions(flow)

            # Create ProgramSlice
            program_slice = ProgramSlice(
                source_location=flow.source_location,
                sink_location=flow.sink_location,
                file_path=flow.source_location.file_path,
                trace_lines=slice_lines,
                variable_definitions=variable_definitions,
                control_structures=control_structures,
                original_lines=0,  # Would be set from file if available
                metadata={
                    "vulnerability_type": flow.vulnerability_type,
                    "source_method": flow.source_method,
                    "sink_method": flow.sink_method,
                },
            )

            return SliceResult(
                flow=flow,
                slice=program_slice,
                success=True,
            )

        except Exception as e:
            return SliceResult(
                flow=flow,
                slice=None,
                success=False,
                error=str(e),
            )

    async def extract_slices(self, flows: list[DataFlow]) -> list[SliceResult]:
        """Extract slices for multiple data flows.

        Args:
            flows: List of data flows.

        Returns:
            List of SliceResults.
        """
        if not flows:
            return []

        if self.config.parallel_extraction:
            return await self._extract_parallel(flows)
        else:
            return await self._extract_sequential(flows)

    async def _extract_parallel(self, flows: list[DataFlow]) -> list[SliceResult]:
        """Extract slices in parallel."""
        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def limited_extract(flow: DataFlow) -> SliceResult:
            async with semaphore:
                return await self.extract_slice(flow)

        tasks = [limited_extract(f) for f in flows]
        return await asyncio.gather(*tasks)

    async def _extract_sequential(self, flows: list[DataFlow]) -> list[SliceResult]:
        """Extract slices sequentially."""
        results = []
        for flow in flows:
            result = await self.extract_slice(flow)
            results.append(result)
        return results

    def _convert_to_slice_lines(
        self,
        slice_data: list[dict[str, Any]],
        trace_line_numbers: set[int],
        source_line: int,
        sink_line: int,
    ) -> list[SliceLine]:
        """Convert Joern slice data to SliceLine objects.

        Args:
            slice_data: Raw slice data from Joern.
            trace_line_numbers: Line numbers that are part of the trace.
            source_line: Source line number.
            sink_line: Sink line number.

        Returns:
            List of SliceLine objects.
        """
        slice_lines = []

        for item in slice_data:
            line_num = item.get("lineNumber", 0)
            code = item.get("code", "")

            # Determine if this line is part of the trace
            is_trace = line_num in trace_line_numbers

            # Determine annotation
            annotation = None
            if line_num == source_line:
                annotation = "SOURCE"
            elif line_num == sink_line:
                annotation = "SINK"
            elif is_trace:
                annotation = "TRACE"

            slice_line = SliceLine(
                line_number=line_num,
                code=code,
                is_trace=is_trace,
                annotation=annotation,
            )
            slice_lines.append(slice_line)

        return sorted(slice_lines, key=lambda x: x.line_number)

    def _prioritize_lines(
        self,
        lines: list[SliceLine],
        trace_lines: set[int],
        max_lines: int,
    ) -> list[SliceLine]:
        """Prioritize lines when over the limit.

        Always keeps trace lines, removes context lines first.

        Args:
            lines: All slice lines.
            trace_lines: Line numbers that must be kept.
            max_lines: Maximum number of lines.

        Returns:
            Prioritized list of lines.
        """
        # Separate trace lines and context lines
        must_keep = [l for l in lines if l.line_number in trace_lines]
        optional = [l for l in lines if l.line_number not in trace_lines]

        # Always keep trace lines
        result = must_keep.copy()

        # Add optional lines up to the limit
        remaining = max_lines - len(result)
        if remaining > 0:
            result.extend(optional[:remaining])

        return sorted(result, key=lambda x: x.line_number)

    async def _get_control_structures(
        self,
        flow: DataFlow,
    ) -> list[dict[str, Any]]:
        """Get control structures affecting the flow.

        Args:
            flow: The data flow.

        Returns:
            List of control structure information.
        """
        try:
            return await self.joern_client.get_control_structures(
                file_path=str(flow.source_location.file_path),
                start_line=flow.source_location.line,
                end_line=flow.sink_location.line,
            )
        except Exception:
            return []

    async def _get_variable_definitions(
        self,
        flow: DataFlow,
    ) -> list[dict[str, Any]]:
        """Get variable definitions for tainted variables.

        Args:
            flow: The data flow.

        Returns:
            List of variable definition information.
        """
        try:
            # Query for variable definitions
            query = f'''
            cpg.method.filename("{flow.source_location.file_path}")
                .assignment
                .filter(_.lineNumber.exists(l => l >= {flow.source_location.line} && l <= {flow.sink_location.line}))
                .map(a => Map(
                    "name" -> a.target.code,
                    "line" -> a.lineNumber.getOrElse(-1),
                    "value" -> a.source.code
                ))
                .toJson
            '''
            result = await self.joern_client.query(query)
            return result.to_json() if result.success else []
        except Exception:
            return []
