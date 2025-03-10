import { registerEnumType } from "@nestjs/graphql";

export enum Action {
  // Actions Génériques
  CREATE = 'create',
  READ = 'read',
  UPDATE = 'update',
  DELETE = 'delete',
  
  // Actions Spécifiques aux Terrains
  VALIDATE = 'validate',
  REJECT = 'reject',
  SIGN = 'sign',
  MEASURE = 'measure',
  REVIEW = 'review',
  UPLOAD_LAND = 'upload_land',      // Pour poster un nouveau terrain
  EDIT_LAND = 'edit_land',          // Pour modifier un terrain
  DELETE_LAND = 'delete_land',      // Pour supprimer un terrain
  VIEW_OWN_LANDS = 'view_own_lands', // Pour voir ses propres terrains
  
  // Actions de Documents
  UPLOAD = 'upload',
  DOWNLOAD = 'download',
  
  // Actions de Validation
  SUBMIT = 'submit',
  APPROVE = 'approve',
  REQUEST_CHANGES = 'request_changes',
  
  // Actions de Notification
  SEND = 'send',
  RECEIVE = 'receive'
}

registerEnumType(Action, {
  name: 'Action',
  description: 'Actions disponibles dans l\'application',
});