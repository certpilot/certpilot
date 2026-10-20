<script setup lang="ts">
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js'
import { Doughnut } from 'vue-chartjs'
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import { useThemeStore } from '@/stores/theme'
import { chartTheme, CHART_FONT_MONO, CHART_FONT_SANS } from '@/lib/chartTheme'

ChartJS.register(ArcElement, Tooltip, Legend)

const { currentTheme } = storeToRefs(useThemeStore())

const props = withDefaults(
  defineProps<{
    labels: string[]
    data: number[]
    colors: string[]
    centerText?: string
    centerSub?: string
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
  datasets: [
    {
      data: props.data,
      backgroundColor: props.colors,
      borderWidth: 0,
      hoverOffset: 6,
    },
  ],
}))

// Legend and tooltip colours come from the theme rather than a fixed dark
// palette, so the chart stays legible after the light/dark toggle.
const chartOptions = computed(() => {
  const t = chartTheme(currentTheme.value)
  return {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '68%',
    animation: props.animate ? undefined : (false as const),
    plugins: {
      legend: {
        display: true,
        position: 'bottom' as const,
        labels: {
          padding: 16,
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
  <div class="relative w-full h-full min-h-[220px]">
    <Doughnut :data="chartData" :options="chartOptions" />
    <!-- Center Text Overlay -->
    <div v-if="centerText" class="absolute inset-0 flex flex-col items-center justify-center pointer-events-none" style="margin-bottom: 32px">
      <span class="text-2xl font-bold">{{ centerText }}</span>
      <span v-if="centerSub" class="text-xs opacity-60">{{ centerSub }}</span>
    </div>
  </div>
</template>
