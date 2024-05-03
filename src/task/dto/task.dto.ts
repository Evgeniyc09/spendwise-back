import { Priority } from '@prisma/client'
import { Transform } from 'class-transformer'
import { IsString, IsOptional, IsBoolean, IsEnum } from 'class-validator'

export class TaskDto {
	@IsString()
	@IsOptional()
	name: string

	@IsBoolean()
	@IsOptional()
	isCompleted?: boolean

	@IsString()
	@IsOptional()
	createdAt?: string

	@IsEnum(Priority)
	@IsOptional()
	@Transform(({ value }) => ('' + value).toLowerCase)
	priority?: Priority
}
