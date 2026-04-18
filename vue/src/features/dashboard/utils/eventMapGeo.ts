export type MapMode = 'china' | 'global'

export const MAP_CONTEXT = 'waf-world-context-pacific'

const PACIFIC_SHIFT_THRESHOLD_LNG = -25

const CHINA_REGION_NAMES = [
  '北京市',
  '天津市',
  '河北省',
  '山西省',
  '内蒙古自治区',
  '辽宁省',
  '吉林省',
  '黑龙江省',
  '上海市',
  '江苏省',
  '浙江省',
  '安徽省',
  '福建省',
  '江西省',
  '山东省',
  '河南省',
  '湖北省',
  '湖南省',
  '广东省',
  '广西壮族自治区',
  '海南省',
  '重庆市',
  '四川省',
  '贵州省',
  '云南省',
  '西藏自治区',
  '陕西省',
  '甘肃省',
  '青海省',
  '宁夏回族自治区',
  '新疆维吾尔自治区',
  '台湾省',
  '香港特别行政区',
  '澳门特别行政区',
]

function isChinaWorldFeature(feature: {
  properties?: Record<string, unknown>
}) {
  const name = String(feature.properties?.name || '').toLowerCase()
  return (
    name === 'china' ||
    name === "people's republic of china" ||
    name === 'republic of china'
  )
}

export function buildContextMap(
  worldGeoJson: {
    type: 'FeatureCollection'
    features: Array<{
      geometry?: { coordinates?: unknown }
      properties?: Record<string, unknown>
    }>
  },
  chinaGeoJson: {
    features: Array<{
      geometry?: { coordinates?: unknown }
      properties?: Record<string, unknown>
    }>
  },
) {
  return {
    ...worldGeoJson,
    type: 'FeatureCollection' as const,
    features: [
      ...worldGeoJson.features.filter(
        (feature) => !isChinaWorldFeature(feature),
      ),
      ...chinaGeoJson.features,
    ],
  }
}

function shiftLongitude(lng: number) {
  return lng < PACIFIC_SHIFT_THRESHOLD_LNG ? lng + 360 : lng
}

export function mapPoint(lng: number, lat: number) {
  return [shiftLongitude(lng), lat]
}

function collectLongitudes(value: unknown, result: number[] = []) {
  if (!Array.isArray(value)) return result
  if (
    value.length >= 2 &&
    typeof value[0] === 'number' &&
    typeof value[1] === 'number'
  ) {
    result.push(value[0])
    return result
  }
  value.forEach((item) => collectLongitudes(item, result))
  return result
}

function shouldShiftFeature(coordinates: unknown) {
  const longitudes = collectLongitudes(coordinates)
  if (longitudes.length === 0) return false
  return Math.max(...longitudes) < PACIFIC_SHIFT_THRESHOLD_LNG
}

function shiftGeoJsonLongitudes<T>(value: T): T {
  if (typeof value === 'number') {
    return shiftLongitude(value) as T
  }
  if (!Array.isArray(value)) {
    return value
  }
  if (
    value.length >= 2 &&
    typeof value[0] === 'number' &&
    typeof value[1] === 'number'
  ) {
    return [shiftLongitude(value[0]), value[1], ...value.slice(2)] as T
  }
  return value.map((item) => shiftGeoJsonLongitudes(item)) as T
}

export function buildPacificMap(geoJson: ReturnType<typeof buildContextMap>) {
  return {
    ...geoJson,
    features: geoJson.features.map((feature) => ({
      ...feature,
      geometry:
        feature.geometry && shouldShiftFeature(feature.geometry.coordinates)
          ? {
              ...feature.geometry,
              coordinates: shiftGeoJsonLongitudes(feature.geometry.coordinates),
            }
          : feature.geometry,
    })),
  }
}

export function geoConfigForMode(mode: MapMode) {
  const chinaMode = mode === 'china'
  return {
    map: MAP_CONTEXT,
    roam: false,
    zoom: chinaMode ? 8 : 1.72,
    center: chinaMode ? [106.3, 36.1] : [158, 12],
    scaleLimit: { min: 0.8, max: 8.5 },
    emphasis: { disabled: true },
    label: { show: false },
    itemStyle: {
      areaColor: chinaMode ? '#111827' : '#172033',
      borderColor: chinaMode ? 'rgba(100, 116, 139, 0.36)' : '#334155',
      borderWidth: chinaMode ? 0.6 : 0.8,
    },
    regions: [
      ...CHINA_REGION_NAMES.map((name) => ({
        name,
        itemStyle: {
          areaColor: chinaMode ? '#1f3b57' : '#1d3a4f',
          borderColor: chinaMode ? '#38bdf8' : 'rgba(56, 189, 248, 0.45)',
          borderWidth: chinaMode ? 0.9 : 0.45,
        },
      })),
      { name: '南海诸岛', itemStyle: { opacity: 0 }, label: { show: false } },
    ],
    animation: false,
  }
}
