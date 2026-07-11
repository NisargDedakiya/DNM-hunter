export interface LearningCenterEntry {
  source: 'skills' | 'community'
  id: string
  name: string
  description: string
  category: string
}

export interface LearningCenterDetail extends LearningCenterEntry {
  content: string
}
