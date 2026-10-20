<script setup lang="ts">
import {
  Chart as ChartJS,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
} from 'chart.js'
import { Bar } from 'vue-chartjs'
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import { useThemeStore } from '@/stores/theme'
import { chartTheme, CHART_FONT_MONO, CHART_FONT_SANS } from '@/lib/chartTheme'

ChartJS.register(BarElement, CategoryScale, LinearScale, Tooltip, Legend)

const { currentTheme } = storeToRefs(useThemeStore())

const props = withDefaults(
  defineProps<{
    labels: string[]
    datasets: { label: string; data: number[]; backgroundColor: string }[]
    /**
     * Animate value changes. Off by default: with live updates arriving, the
     * chart.js default 1000ms tween restarts on every tick and the chart never
     * settles.
     */
    animate?: boolean
  }>(),
  { animate: false },
)

const chartData = computed(() => ({
  labels: props.labels,
  datasets: props.datasets.map(ds => ({
    ...ds,
    borderRadius: 6,
    borderSkipped: false as const,
    maxBarThickness: 40,
  })),
}))

// Axis, grid, and tooltip colours follow the theme; a fixed palette left the
// tick labels effectively invisible in one of the two themes.
const chartOptions = computed(() => {
  const t = chartTheme(currentTheme.value)
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: props.animate ? undefined : (false as const),
    scales: {
      x: {
        grid: { display: false },
        ticks: { color: t.text, font: { size: 10, family: CHART_FONT_SANS } },
      },
      y: {
        beginAtZero: true,
        grid: { color: t.grid },
        ticks: { color: t.text, font: { size: 10, family: CHART_FONT_MONO }, stepSize: 1 },
      },
    },
    plugins: {
      legend: {
        display: props.datasets.length > 1,
        position: 'bottom' as const,
        labels: {
          padding: 14,
          usePointStyle: true,
          pointStyleWidth: 8,
          color: t.text,
          font: { size: 11, family: CHART_FONT_SANS },
        },
      },
      tooltip: {
        backgroundColor: t.tooltipBg,
        titleColor: t.tooltipText,
        bodyColor: t.tooltipText,
        titleFont: { family: CHART_FONT_SANS, size: 12 },
        bodyFont: { family: CHART_FONT_MONO, size: 11 },
        padding: 10,
        cornerRadius: 8,
      },
    },
  }
})
</script>

<template>
  <div class="w-full h-full min-h-[220px]">
    <Bar :data="chartData" :options="chartOptions" />
  </div>
</template>
