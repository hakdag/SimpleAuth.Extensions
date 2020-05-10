using SimpleAuthExtensions.Service;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SimpleAuthExtensions.Business
{
    public interface ISimpleAuthBusiness
    {
        Task<ResponseResult> LockAccount(long userId);
        Task<ResponseResult> UnLockAccount(long userId);
        Task<ResponseResult> ChangePassword(string userName, string oldPassword, string password, string passwordConfirm);
        
        // Roles
        Task<ICollection<RoleVM>> GetRoles();
        Task<RoleVM> GetRole(long id);
        Task<ResponseResult> CreateRole(CreateRoleVM role);
        Task<ResponseResult> UpdateRole(UpdateRoleVM role);
        Task<ResponseResult> DeleteRole(long id);

        // UserRole
        Task<ResponseResult> AddUserToRole(UserRoleVM userRole);
        Task<ResponseResult> RemoveUserFromRole(UserRoleVM userRole);

        // Users
        Task<ICollection<UserVM>> GetUsers();
        Task<UserVM> GetUser(long id);
        Task<ResponseResult> CreateUser(CreateUserVM user);
        Task<ResponseResult> UpdateUser(UpdateUserVM user);
        Task<ResponseResult> DeleteUser(long id);
    }
}
