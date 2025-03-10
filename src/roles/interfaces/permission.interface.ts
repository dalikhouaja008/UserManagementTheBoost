import { Resource } from '../enums/resource.enum';
import { Action } from '../enums/action.enum';

export interface Permission {
  resource: Resource;
  actions: Action[];
}